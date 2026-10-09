# Helpers and validators for ignite.sh. Sourced — not run directly.

# Function: prints a help message.
display_usage() {
    cat << EOF 1>&2
  Usage: ignite.sh [options]
  Options:
    -d DOMAIN              Domain to certify: hostname, *.wildcard or IPv4 — required
    -s SELF_SIGNED        1 = self-signed certificate (default), 0 = CSR only
    -n NUMBITS            RSA key size: 2048 (default), 3072, or 4096
    -t DURATION           Certificate validity in days (self-signed; 1-3650)
    -f CONFIGURATION_FILE openssl config file (mutually exclusive with -i)
    -i SUBJECT            Subject string, e.g. /C=PT/O=Acme/CN=example.com (with -f: -f wins)
    -a SUBJECT_CA         CA subject string (self-signed only)
    -g TEMPLATE           1 = write a .cfg template for DOMAIN and exit
    -k PRIVATE_KEY        .key file to pair with -r when building a .pem
    -r CRT_FILE           .crt file to convert into .cert (and .pem with -k)
    -o OUTPUT_DIR         Where to write output (default ./certificates)
    -I INSTALL_FILE       Install this certificate (see -T; system store needs root)
    -N INSTALL_NAME       Filename to install it as (default: younglings-<fingerprint>.crt)
    -U                    With -I: REMOVE that certificate from the store instead
    -T INSTALL_TARGET     Where -I installs: system, nss, or all (default all)
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
    while getopts ":d:s:n:t:f:i:a:g:k:r:o:I:N:T:Uh" option; do
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
            o) OUTPUT_DIR="$OPTARG" ;;
            I) INSTALL_FILE="$OPTARG" ;;
            N) INSTALL_NAME="$OPTARG" ;;
            T) INSTALL_TARGET="$OPTARG" ;;
            U) UNINSTALL="1" ;;
            h) display_usage; exit 0 ;;
            :) parameter_missing_error "Option -$OPTARG requires a value." ;;
            \?|*) parameter_missing_error "$ERR_UO: -$OPTARG" ;;
        esac
    done
}

# Function: is $1 a dotted-quad IPv4 address?
is_ipv4() { printf '%s' "${1:-}" | grep -Eq "$re_ipv4"; }

# Function: validate a domain: hostname (example.com, localhost, myhost),
# wildcard (*.example.com) or IPv4 address.
validate_domain() {
    local domain="${1:-}"
    [ -z "$domain" ] && parameter_missing_error "$ERR_DN_NS"
    if printf '%s' "$domain" | grep -Eq '^[0-9.]+$'; then
        is_ipv4 "$domain" || execution_error "$ERR_DN_I"    # all-numeric: must be a real IPv4
    elif ! printf '%s' "$domain" | grep -Eq "$re_hostname"; then
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

# Function: recompute the output path from the parsed flags.
#
# variables.sh is sourced BEFORE read_parameters runs, so CERTIFICATES_PATH is
# first computed while OUTPUT_DIR is still empty. Without this, -o parses
# cleanly, changes nothing, and every file lands in ./certificates anyway —
# which is worse than rejecting the flag, because the caller is told where the
# key went and it is not there.
resolve_paths() {
    CERTIFICATES_PATH="${OUTPUT_DIR:-$CERTIFICATES_DIR}"
}

# Function: validate the certificate handed to -I.
#
# Checked for content, not extension: a .crt that is actually a CSR or a key is
# the mistake worth catching, and installing a private key into a world-readable
# anchors directory is the one that would hurt.
validate_install_file() {
    [ -n "${1:-}" ] || parameter_missing_error "$ERR_INST_FNF"
    [ -f "$1" ] || execution_error "$ERR_INST_FNF: $1"
    # Parsed by openssl, not matched as text. `grep 'BEGIN CERTIFICATE'` accepts
    # a CSR, because "-----BEGIN CERTIFICATE REQUEST-----" contains that
    # substring — so a CSR would have been installed as a trust anchor. openssl
    # x509 succeeds only for an actual certificate.
    openssl x509 -noout -in "$1" >/dev/null 2>&1 \
        || execution_error "$ERR_INST_NC: $1"
    # A certificate file should not carry a key. If it does, installing it would
    # copy a private key into a world-readable anchors directory.
    if grep -q 'PRIVATE KEY' "$1"; then
        execution_error "Refusing to install a file containing a PRIVATE KEY: $1"
    fi
}

# Function: pick the trust store this machine actually uses.
#
# Sets TRUST_ANCHORS and TRUST_UPDATE. Detection is by the presence of the
# anchors directory AND its update command, so a half-installed ca-certificates
# package fails with a clear reason instead of a copy that never takes effect.
detect_trust_store() {
    if [ -d "$TRUST_ANCHORS_RHEL" ]; then
        TRUST_ANCHORS="$TRUST_ANCHORS_RHEL"
        TRUST_UPDATE="$TRUST_UPDATE_RHEL"
    elif [ -d "$TRUST_ANCHORS_DEBIAN" ]; then
        TRUST_ANCHORS="$TRUST_ANCHORS_DEBIAN"
        TRUST_UPDATE="$TRUST_UPDATE_DEBIAN"
    else
        execution_error "$ERR_INST_NS"
    fi
    command -v "$TRUST_UPDATE" >/dev/null 2>&1 \
        || execution_error "$ERR_INST_NU: $TRUST_UPDATE"
}

# Function: validate -T.
# -N becomes a filename inside a root-owned trust directory, so it is
# restricted rather than trusted: a '/' in it writes wherever it points, as
# root, and a leading '.' hides the anchor from the person looking for it.
validate_install_name() {
    [ -n "${1:-}" ] || return 0   # empty = the default, see _anchor_base
    case "$1" in
        */*|.*) parameter_missing_error "$ERR_INST_NAME: ${1}" ;;
    esac
}

validate_install_target() {
    case "${1:-}" in
        system|nss|all) return 0 ;;
        *) parameter_missing_error "$ERR_INST_TGT: ${1:-}" ;;
    esac
}

# Function: whose NSS databases to touch.
#
# Under sudo, $HOME is root's. The system store needs root and the NSS stores
# belong to the person at the keyboard, so `sudo ignite -I ca.crt` would
# otherwise install the anchor correctly and then populate root's browser
# profiles — leaving the browsers exactly as untrusting as before, with nothing
# to indicate why.
nss_user() { printf '%s' "${SUDO_USER:-$(id -un)}"; }
nss_home() {
    local u; u="$(nss_user)"
    getent passwd "$u" 2>/dev/null | cut -d: -f6
}

# Function: print every NSS database on this machine, one path per line.
#
# Chromium-family browsers and Firefox do not read the OpenSSL system store at
# all; they read NSS. Flatpaks multiply that: each app declaring persistent=.pki
# gets its own database under ~/.var/app/<id>/, so a system-wide entry reaches
# none of them.
discover_nss_stores() {
    local home; home="$(nss_home)"
    [ -n "$home" ] || return 0
    {
        # Native Chromium, Chrome, and anything else using the shared user db.
        printf '%s\n' "$home/.pki/nssdb"
        # Flatpak apps with persistent=.pki.
        printf '%s\n' "$home"/.var/app/*/data/pki/nssdb
        printf '%s\n' "$home"/.var/app/*/.pki/nssdb
        # Snap-packaged browsers.
        printf '%s\n' "$home"/snap/*/current/.pki/nssdb
        # Firefox keeps its own database per PROFILE and ignores both the system
        # store and ~/.pki/nssdb, which is why it still warns when every
        # Chromium browser has stopped.
        printf '%s\n' "$home"/.mozilla/firefox/*/
        printf '%s\n' "$home"/.var/app/org.mozilla.firefox/.mozilla/firefox/*/
    } 2>/dev/null | while read -r d; do
        # A real database, not an unexpanded glob: cert9.db (sql) or cert8.db.
        [ -f "${d%/}/cert9.db" ] || [ -f "${d%/}/cert8.db" ] || continue
        printf '%s\n' "${d%/}"
    done
}
