# Function: prints a help message.
# Usage example:
# display_usage
display_usage() {
    cat << EOF 1>&2
  Usage: $0 [options]
  Options:
    -d DOMAIN              Set the domain to get certified
    -s SELF_SIGNED         Set the certificate to be self-signed
    -n NUMBITS             Set the value of bits to be used in the generation process
    -t DURATION            Set the duration of the certificate in days
    -f CONFIGURATION_FILE  Set the name of the external configuration file (ignores the subject option)
    -i SUBJECT             Set the subject string for the certificate (ignores the configuration file option)
    -a SUBJECT_CA          Set the subject string for the certificate authority if self-signed
    -g TEMPLATE            Generate a configuration file template (needs a domain parameter)
    -k PRIVATE_KEY         Set the name of the .KEY file to use for generating a .PEM file.
    -r CRT_FILE            Set the name of the .CRT file to use for generating a .PEM file.
EOF
}

# Function: prints message in green.
# Usage example:
# msg "some message"
msg(){
    local message="$1"
    if [ -n "$message" ]; then
        printf "${GREEN} $message${NC}\n" 
    fi
}

# Function: prints error message in yellow.
# Usage example:
# wrn "some message"
wrn(){
    local message="$1"
    if [ -n "$message" ]; then
        printf "${YELLOW} $message${NC}\n" 
    fi
}

# Function: prints error message in red.
# Usage example:
# oerr "some message"
oerr(){
    local message="$1"
    if [ -n "$message" ]; then
        printf "${RED} Error: $message${NC}\n" 
    fi
}

# Function: exits with message.
# Usage example:
# trap execution_error ERR
# execution_error "$ERR"
execution_error() {
    local err_code="$1"
    if [ -n "$err_code" ]; then
        oerr "$err_code"
    fi
    oerr "$ERR_EE"
    exit 1
}

# Function: exits with help message.
# Usage example:
# parameter_missing_error $ERR
parameter_missing_error() {
    local err_message=$1
    if [ -n "$err_message" ]; then
        wrn "$err_message"
    fi
    display_usage
    exit 1
}

# Function: read parameters from command line.
# Usage example:
# read_parameters "$@"
read_parameters() {
  while getopts ":d:s:n:t:e:p:a:" options; do
    case "${options}" in
      d)
        DOMAIN=${OPTARG}
        ;;
      s)
        SELF_SIGNED=${OPTARG}
        ;;
      n)
        NUMBITS=${OPTARG}
        ;;
      t)
        if [ -n "$SELF_SIGNED" ]; then
          DURATION=${OPTARG}
        fi
        ;;
      f)
        CONFIGURATION_FILE=${OPTARG}
        ;;
      i)
        SUBJECT=${OPTARG}
        ;;
      a)
        if [ -n "$SELF_SIGNED" ]; then
          SUBJECT_CA=${OPTARG}
        fi
        ;;
      g)
        TEMPLATE=${OPTARG}
        ;;
      k)
        PRIVATE_KEY=${OPTARG}
        ;;
      r)
        CRT_FILE=${OPTARG}
        ;;
      *)
        execution_error "$ERR_UO"
        ;;
    esac
  done
}

# Function: validates a domain name parameter.
# Usage example:
# validate_domain "$DOMAIN"
validate_domain() {
    local domain="$1"
    if [ -z "$domain" ]; then
        parameter_missing_error "$ERR_DN_NS"
    fi
    if ! echo "$domain" | grep -Eq '^([a-zA-Z0-9](-*[a-zA-Z0-9])*\.)+[a-zA-Z]{2,63}$'; then
        execution_error "$ERR_DN_I"
    fi
}

# Function: validates the configuration file generation flag.
# Checks if is set and if the value is valid.
# Usage example:
# validate_template_flag "$TEMPLATE"
validate_template_flag() {
    local generate=$1
    if [ -z "$generate" ]; then
        # must be set - maybe with a default value
        parameter_missing_error "$ERR_TPLF_NS"
    fi
    if ! echo "$port" | grep -qE '^[01]$'; then
        # must be 0 or 1
        execution_error "$ERR_TPLF_I"
    fi
}

validate_self_signed() {
    local signed=$1
    if [ -z "$signed" ]; then
        # must be set - maybe with a default value
        parameter_missing_error "$ERR_SSF_NS"
    fi
    if ! echo "$port" | grep -qE '^[01]$'; then
        # must be 0 or 1
        execution_error "$ERR_SSF_I"
    fi
}

validate_numbits() {
    local numbits="$1"
    if !echo "$numbits" | grep -Eq '^(2048|3072|4096)$'; then
        execution_error "$ERR_BN_I"
    fi
}

validate_duration() {
    local days="$1"
    if ! echo "$days" | grep -Eq '^[0-9]+$' && [ "$days" -ge 1 ] && [ "$days" -le 3650 ]; then
        execution_error "$ERR_CD_I"
    fi
}

# Function: validates the token input.
# Also reads the token value from its file.
# Usage example:
# validate_token "$TOKEN"
validate_configuration_file(){
  local config_file_name=$1
    if [ -z "$config_file_name" ]; then
        parameter_missing_error "$ERR_CFG_FNS"
    fi
    local config_file_path=$(eval echo "$config_file_name")
    msg "Verifying configuration file: $config_file_path"
    if [ ! -f "$config_file_path" ]; then
        execution_error "$ERR_CFG_FNF"
    fi
    msg "Loading configurations."
    $CONFIGURATIONS=$(cat "$config_file_path")
    msg "Configurations loaded."
}

validate_crt_file(){
  local crt_file_name=$1
    if [ -z "$crt_file_name" ]; then
        wrn "$ERR_CRT_FNS"
    fi
}

validate_private_key_file(){
  local key_file_name=$1
    if [ -z "$key_file_name" ]; then
        wrn "$ERR_KEY_FNS"
    fi
}

# Function to check if a field is present
is_present() {
    echo "$1" | grep -q "$2"
}

validate_subject(){
  local subject_string=$1
  if echo "$subject_string" | grep -Eq "$re_subject"; then
    if !is_present "$subject_string" "/C=" || !is_present "$subject_string" "/CN=" || !is_present "$subject_string" "/O="; then
      # does not have the required fields
      execution_error "$ERR_SS_MI"
    fi
  else
    # its garbled
    execution_error "$ERR_SS_I"
  fi
}

# Function: execute commands with enhanced error handling.
# Usage example:
# execute apt update
# execute apt install -y kubelet kubeadm kubectl kubectx
execute() {
    "$@"
    local status=$?
    if [ $status -ne 0 ]; then
        execution_error " Error: Failed executing - '$*'"
    fi
}

# Function: execute commands with error handling (no vars printed).
# Usage example:
# execute_sensitive apt update
# execute_sensitive apt install -y kubelet kubeadm kubectl kubectx
execute_sensitive() {
    "$@"
    local status=$?
    if [ $status -ne 0 ]; then
        execution_error "$ERR_FEC"
    fi
}

# Function: execute commands ignoring resulting errors.
# Usage example:
# execute_non_blocking apt install -y kubelet kubeadm kubectl kubectx
execute_non_blocking() {
   "$@"
    local status=$?
    if [ $status -ne 0 ]; then
        oerr "$ERR_FEC"
    fi 
}

# Generate a .cert file and .pem file from the .crt file (needs k PRIVATE_KEY, r CRT_FILE parameters)
generate_files_from_crt(){
  # ensure the path is set
  $CERTIFICATES_PATH= "$SCRIPT_DIR/$CERTIFICATES_DIR"
  execute mkdir -p $CERTIFICATES_PATH

  # validate .CRT file exists
  if [ ! -f "$CERTIFICATES_PATH/$CRT_FILE" ]; then
        execution_error "$ERR_CRT_FNF"
  fi
  # validate .KEY file exists
  if [ ! -f "$CERTIFICATES_PATH/$PRIVATE_KEY" ]; then
        execution_error "$ERR_KEY_FNF"
  fi
  # Check it
  execute openssl x509 -text -noout -in "$CERTIFICATES_PATH/$CRT_FILE"
  # Generate the .cert file that some systems might request
  execute openssl x509 -inform PEM -in "$CERTIFICATES_PATH/$CRT_FILE" -out "$CERTIFICATES_PATH/$DOMAIN.cert"
  # Generate the .pem file for your certificate
  execute cat "$CERTIFICATES_PATH/$PRIVATE_KEY" "$CERTIFICATES_PATH/$CRT_FILE" > "$CERTIFICATES_PATH/$DOMAIN.pem"
}

# Generate a configuration file template (needs g TEMPLATE parameter, requires DOMAIN parameter)
generate_configuration_file_template(){
  cat > "$CERTIFICATES_PATH/$DOMAIN.cfg" <<-EOF
[ req ]
default_bits        = 2048
default_keyfile     = vaiken.spacedock.key # provide vaiken.spacedock value as the domain parameter 
default_md          = sha256
distinguished_name  = req_distinguished_name
req_extensions      = req_ext
x509_extensions     = v3_ca # Extensions to add for self-signed certs (if needed)

[ req_distinguished_name ]
countryName          =
countryName_default  = US
stateOrProvinceName  =
stateOrProvinceName_default  = Drommund Kaas
localityName         =
localityName_default = Kaas City
organizationName     = 
organizationName_default = Sith Empire
commonName           = $DOMAIN 
commonName_default   = vaiken.spacedock
commonName_max       = 64

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1   = vaiken.spacedock
DNS.2   = www.vaiken.spacedock
DNS.3   = cantina.vaiken.spacedock
DNS.4   = supplies.vaiken.spacedock
DNS.5   = crew-skills.vaiken.spacedock
DNS.6   = combat-training.vaiken.spacedock
DNS.7   = galatic-trade-market.vaiken.spacedock
# Add more DNS.8, DNS.9, etc., as needed
#IP.1    = 192.168.1.141
# Add more IP.2, IP.3, etc., as needed
EOF
  wrn "File generated: $CERTIFICATES_PATH/$DOMAIN.cfg"
}

## tests
parse_configurations(){
  # Read the file and parse it
  local section=""
  while IFS= read -r line || [ -n "$line" ]; do
    # Check if the line is a section header
    if echo "$line" | grep -q "^\[.*\]$"; then
        section=$(echo "$line" | sed 's/[][]//g')
        echo "Section: $section"
    # Check if the line contains a key-value pair
    elif echo "$line" | grep -q "^[^#]*="; then
        key=$(echo "$line" | cut -d '=' -f 1 | tr -d ' ')
        value=$(echo "$line" | cut -d '=' -f 2- | sed 's/^ *//;s/ *$//')
        echo "Key: $key, Value: $value"
    fi
  done < "$1"
}