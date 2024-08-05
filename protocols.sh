# Self Signed Certificate - initialization
self_signed_protocol(){
  if [ -z "$CONFIGURATIONS" ]; then
    self_signed_protocol_configured
  else
    self_signed_protocol_subject
  fi
}
# Self Signed Protocol with configuration file
self_signed_protocol_configured(){
  # validate encryption bits value
  validate_numbits $NUMBITS
  # validate certificate duration
  validate_duration $DURATION
  # validate the certificate authority information
  validate_subject $SUBJECT_CA
  
  $CERTIFICATES_PATH = "$SCRIPT_DIR/$CERTIFICATES_DIR"
  execute mkdir -p $CERTIFICATES_PATH

  # Generate the CA key
  execute openssl genrsa -out "$CERTIFICATES_PATH/ca.key" $NUMBITS
  # Generate the CA certificate
  execute openssl req -x509 -new -nodes -sha512 -days $TIME -subj $SUBJECT_CA -key "$CERTIFICATES_PATH/ca.key" -out "$CERTIFICATES_PATH/ca.crt"
  # Generate your private key
  execute openssl genrsa -out "$CERTIFICATES_PATH/$DOMAIN.key" $NUMBITS
  # Generate your certificate signing request
  execute openssl req -sha512 -new -key "$CERTIFICATES_PATH/$DOMAIN.key" -out "$CERTIFICATES_PATH/$DOMAIN.csr" -config "$CONFIGURATION_FILE"
  # Check the CSR file
  execute openssl req -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.csr"
  # Sign your certificate using the CA
  execute openssl x509 -req -sha512 -days $TIME -CA "$CERTIFICATES_PATH/ca.crt" -CAkey "$CERTIFICATES_PATH/ca.key" -CAcreateserial -in "$CERTIFICATES_PATH/$DOMAIN.csr" -out "$CERTIFICATES_PATH/$DOMAIN.crt"
  # Check it
  execute openssl x509 -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.crt"
  # Generate the .cert file that some systems might request
  execute openssl x509 -inform PEM -in "$CERTIFICATES_PATH/$DOMAIN.crt" -out "$CERTIFICATES_PATH/$DOMAIN.cert"
  # Generate the .pem file for your certificate
  execute cat "$CERTIFICATES_PATH/$DOMAIN.key" "$CERTIFICATES_PATH/$DOMAIN.crt" > "$CERTIFICATES_PATH/$DOMAIN.pem"
}
# Self Signed Protocol with configuration string - subject
self_signed_protocol_subject(){
  # validate encryption bits value
  validate_numbits $NUMBITS
  # validate certificate duration
  validate_duration $TIME
  # validate the certificate authority information
  validate_subject $SUBJECT_CA
  # validate the certificate information
  validate_subject $SUBJECT
  
  $CERTIFICATES_PATH = "$SCRIPT_DIR/$CERTIFICATES_DIR"
  execute mkdir -p $CERTIFICATES_PATH

  # Generate the CA key
  execute openssl genrsa -out "$CERTIFICATES_PATH/ca.key" $NUMBITS
  # Generate the CA certificate
  execute openssl req -x509 -new -nodes -sha512 -days $TIME -subj $SUBJECT_CA -key "$CERTIFICATES_PATH/ca.key" -out "$CERTIFICATES_PATH/ca.crt"
  # Generate your private key
  execute openssl genrsa -out "$CERTIFICATES_PATH/$DOMAIN.key" $NUMBITS
  # Generate your certificate signing request
  execute openssl req -sha512 -new -subj $SUBJECT -key "$CERTIFICATES_PATH/$DOMAIN.key" -out "$CERTIFICATES_PATH/$DOMAIN.csr"
  # Check the CSR file
  execute openssl req -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.csr"
  # Sign your certificate using the CA
  execute openssl x509 -req -sha512 -days $TIME -CA "$CERTIFICATES_PATH/ca.crt" -CAkey "$CERTIFICATES_PATH/ca.key" -CAcreateserial -in "$CERTIFICATES_PATH/$DOMAIN.csr" -out "$CERTIFICATES_PATH/$DOMAIN.crt"
  # Check it
  execute openssl x509 -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.crt"
  # Generate the .cert file that some systems might request
  execute openssl x509 -inform PEM -in "$CERTIFICATES_PATH/$DOMAIN.crt" -out "$CERTIFICATES_PATH/$DOMAIN.cert"
  # Generate the .pem file for your certificate
  execute cat "$CERTIFICATES_PATH/$DOMAIN.key" "$CERTIFICATES_PATH/$DOMAIN.crt" > "$CERTIFICATES_PATH/$DOMAIN.pem"
}
# Certificate Request - initialization
certificate_request_protocol(){
  if [ -z "$CONFIGURATIONS" ]; then
    certificate_request_protocol_configured
  else
    certificate_request_protocol_subject
  fi
}
# Certificate Request with configuration string - subject
certificate_request_protocol_subject(){
  # validate encryption bits value
  validate_numbits $NUMBITS
  # validate the certificate information
  validate_subject $SUBJECT
  
  $CERTIFICATES_PATH = "$SCRIPT_DIR/$CERTIFICATES_DIR"
  execute mkdir -p $CERTIFICATES_PATH
  
  # Generate your private key
  execute openssl genrsa -out "$CERTIFICATES_PATH/$DOMAIN.key" $NUMBITS
  # Generate your certificate signing request
  execute openssl req -sha512 -new -subj $SUBJECT -key "$CERTIFICATES_PATH/$DOMAIN.key" -out "$CERTIFICATES_PATH/$DOMAIN.csr"
  # Check the CSR file
  execute openssl req -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.csr"
}
# Certificate Request with configuration file
certificate_request_protocol_configured(){
  # validate encryption bits value
  validate_numbits $NUMBITS
  
  $CERTIFICATES_PATH = "$SCRIPT_DIR/$CERTIFICATES_DIR"
  execute mkdir -p $CERTIFICATES_PATH

  # Generate your private key
  execute openssl genrsa -out "$CERTIFICATES_PATH/$DOMAIN.key" $NUMBITS
  # Generate your certificate signing request
  execute openssl req -sha512 -new -key "$CERTIFICATES_PATH/$DOMAIN.key" -out "$CERTIFICATES_PATH/$DOMAIN.csr" -config "$CONFIGURATION_FILE"
  # Check the CSR file
  execute openssl req -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.csr"
}

# Decides which file generation protocol to follow
generate_file_protocol(){
  local protocol_requested = $1
  if [ "$protocol_requested" -eq "$PEM_AND_CERT_FILES" ]; then 
    generate_files_from_crt_protocol  
  elif [ "$protocol_requested" -eq "$CONFIGURATION_FILE_TEMPLATE" ]; then
    generate_configuration_file_template_protocol
  else
    execution_error "ERR_UP"
  fi
}
# Generate a .cert file and .pem file from the .crt file
generate_files_from_crt_protocol(){
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
# Generate a configuration file template
generate_configuration_file_template_protocol(){
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