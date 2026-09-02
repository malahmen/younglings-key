#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# ignite.sh — certificate generation, simplified.
#
# A gum-free, flag-driven CLI around openssl. Generates CSRs, self-signed
# certificates (with their own CA), .cfg templates, and .cert/.pem files from an
# existing .crt. Output is written under ./certificates in the current directory.
#
# Only dependency: openssl. Run --help for options.
# -----------------------------------------------------------------------------

set -euo pipefail

# Directory of this script — used only to source its sibling modules.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Load the modules (order matters: constants/parameters before variables).
. "$SCRIPT_DIR/regex.sh"       # validation regular expressions
. "$SCRIPT_DIR/colors.sh"      # terminal colours
. "$SCRIPT_DIR/parameters.sh"  # default parameter values
. "$SCRIPT_DIR/constants.sh"   # configuration constants
. "$SCRIPT_DIR/variables.sh"   # derived variables (needs constants + parameters)
. "$SCRIPT_DIR/errors.sh"      # error messages
. "$SCRIPT_DIR/functions.sh"   # helpers, validators
. "$SCRIPT_DIR/protocols.sh"   # generation flows

# No arguments → show usage.
[ "$#" -eq 0 ] && { display_usage; exit 0; }

# Read parameters from the command line.
read_parameters "$@"

# openssl is the only hard dependency.
command -v openssl >/dev/null 2>&1 || execution_error "$ERR_OPENSSL"

# ---- Mode 1: build .cert (+ .pem) from an existing .crt -----------------------
# Chosen by providing -r <crt> (and optionally -k <key> for the .pem).
if [ -n "$CRT_FILE" ]; then
    validate_domain "$DOMAIN"                 # used for the output filenames
    generate_file_protocol "$PEM_AND_CERT_FILES"
    exit 0
fi

validate_domain "$DOMAIN"

# ---- Mode 2: emit a .cfg template and exit ------------------------------------
validate_template_flag "$TEMPLATE"
if [ "$TEMPLATE" = "1" ]; then
    generate_file_protocol "$CONFIGURATION_FILE_TEMPLATE"
    exit 0
fi

# ---- Mode 3: self-signed certificate or CSR -----------------------------------
validate_self_signed "$SELF_SIGNED"
validate_numbits "$NUMBITS"

# Subject source: a config file (-f) OR a subject string (-i), not neither.
if [ -n "$CONFIGURATION_FILE" ]; then
    validate_configuration_file "$CONFIGURATION_FILE"
elif [ -n "$SUBJECT" ]; then
    validate_subject "$SUBJECT"
else
    parameter_missing_error "$ERR_SUBJ_SRC"
fi

if [ "$SELF_SIGNED" = "1" ]; then
    validate_subject "$SUBJECT_CA"            # self-signed needs a CA subject
    validate_duration "$DURATION"
    self_signed_protocol
else
    certificate_request_protocol
fi

exit 0
