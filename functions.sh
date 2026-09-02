# Helpers and validators for ignite.sh. Sourced — not run directly.

# Function: prints a help message.
display_usage() {
    cat << EOF 1>&2
  Usage: ignite.sh [options]
  Options:
    -d DOMAIN              Domain to certify (e.g. example.com) — required
    -s SELF_SIGNED        1 = self-signed certificate (default), 0 = CSR only
    -n NUMBITS            RSA key size: 2048 (default), 3072, or 4096
    -t DURATION           Certificate validity in days (self-signed; 1-3650)
    -f CONFIGURATION_FILE openssl config file (mutually exclusive with -i)
    -i SUBJECT            Subject string, e.g. /C=PT/O=Acme/CN=example.com (with -f: -f wins)
    -a SUBJECT_CA         CA subject string (self-signed only)
    -g TEMPLATE           1 = write a .cfg template for DOMAIN and exit
    -k PRIVATE_KEY        .key file to pair with -r when building a .pem
    -r CRT_FILE           .crt file to convert into .cert (and .pem with -k)
    -h                    Show this help and exit
EOF
}

# Colour print helpers. The message is a printf ARGUMENT (never the format), so
# a '%' in a message can't break printf or inject a format directive.
msg() { [ -n "${1:-}" ] && printf '%b %s%b\n' "$GREEN" "$1" "$NC"; return 0; }
wrn() { [ -n "${1:-}" ] && printf '%b %s%b\n' "$YELLOW" "$1" "$NC" 1>&2; return 0; }
oerr() { [ -n "${1:-}" ] && printf '%b Error: %s%b\n' "$RED" "$1" "$NC" 1>&2; return 0; }

# Function: print an error and exit.
execution_error() {
    [ -n "${1:-}" ] && oerr "$1"
    oerr "$ERR_EE"
    exit 1
}

# Function: warn, show usage, and exit (for missing/invalid parameters).
parameter_missing_error() {
    [ -n "${1:-}" ] && wrn "$1"
    display_usage
    exit 1
}

# Function: read parameters from the command line.
read_parameters() {
    local option
    while getopts ":d:s:n:t:f:i:a:g:k:r:h" option; do
        case "$option" in
            d) DOMAIN="$OPTARG" ;;
            s) SELF_SIGNED="$OPTARG" ;;
            n) NUMBITS="$OPTARG" ;;
            t) DURATION="$OPTARG" ;;
            f) CONFIGURATION_FILE="$OPTARG" ;;
            i) SUBJECT="$OPTARG" ;;
            a) SUBJECT_CA="$OPTARG" ;;
            g) TEMPLATE="$OPTARG" ;;
            k) PRIVATE_KEY="$OPTARG" ;;
            r) CRT_FILE="$OPTARG" ;;
            h) display_usage; exit 0 ;;
            :) parameter_missing_error "Option -$OPTARG requires a value." ;;
            \?|*) parameter_missing_error "$ERR_UO: -$OPTARG" ;;
        esac
    done
}

# Function: validate a domain name.
validate_domain() {
    local domain="${1:-}"
    [ -z "$domain" ] && parameter_missing_error "$ERR_DN_NS"
    if ! printf '%s' "$domain" | grep -Eq '^([a-zA-Z0-9](-*[a-zA-Z0-9])*\.)+[a-zA-Z]{2,63}$'; then
        execution_error "$ERR_DN_I"
    fi
}

# Function: validate the template flag (must be 0 or 1).
validate_template_flag() {
    local flag="${1:-}"
    [ -z "$flag" ] && parameter_missing_error "$ERR_TPLF_NS"
    printf '%s' "$flag" | grep -qE '^[01]$' || execution_error "$ERR_TPLF_I"
}

# Function: validate the self-signed flag (must be 0 or 1).
validate_self_signed() {
    local flag="${1:-}"
    [ -z "$flag" ] && parameter_missing_error "$ERR_SSF_NS"
    printf '%s' "$flag" | grep -qE '^[01]$' || execution_error "$ERR_SSF_I"
}

# Function: validate the RSA key size.
validate_numbits() {
    local numbits="${1:-}"
    printf '%s' "$numbits" | grep -Eq '^(2048|3072|4096)$' || execution_error "$ERR_BN_I"
}

# Function: validate the certificate duration (integer days, 1-3650).
validate_duration() {
    local days="${1:-}"
    if ! printf '%s' "$days" | grep -Eq '^[0-9]+$'; then execution_error "$ERR_CD_I"; fi
    if [ "$days" -lt 1 ] || [ "$days" -gt 3650 ]; then execution_error "$ERR_CD_I"; fi
}

# Function: check a configuration file is present and readable.
validate_configuration_file() {
    local config_file="${1:-}"
    [ -z "$config_file" ] && parameter_missing_error "$ERR_CFG_FNS"
    [ -f "$config_file" ] || execution_error "$ERR_CFG_FNF"
    msg "Using configuration file: $config_file"
}

# Function: is field $2 present in string $1 (fixed-string match).
is_present() { printf '%s' "$1" | grep -qF "$2"; }

# Function: validate a subject string (any field order; needs /C=, /O=, /CN=).
validate_subject() {
    local subject="${1:-}"
    [ -z "$subject" ] && execution_error "$ERR_SS_I"
    printf '%s' "$subject" | grep -Eq "$re_subject" || execution_error "$ERR_SS_I"
    if ! is_present "$subject" "/C=" || ! is_present "$subject" "/O=" || ! is_present "$subject" "/CN="; then
        execution_error "$ERR_SS_MI"
    fi
}

# Function: run a command, aborting with an error if it fails.
# Redirections attach to the call (e.g. `execute cat a b > c`).
execute() {
    if ! "$@"; then
        execution_error "$ERR_FEC ('$*')"
    fi
}
