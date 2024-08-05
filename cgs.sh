#!/bin/sh

# checks for permissions before executing.
if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root. Trying with sudo..."
    exec sudo HOME="$HOME" "$0" "$@"
    exit 1
fi
echo "Certificates Generation Simplified."

# Get the current directory of this script.
$SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Loads the external files in the same directory
. "$SCRIPT_DIR/regex.sh" # loads regular expressions for validation.
. "$SCRIPT_DIR/colors.sh" # loads terminal colors.
. "$SCRIPT_DIR/parameters.sh" # loads parameters default values.
. "$SCRIPT_DIR/constants.sh" # loads configuration constants.
. "$SCRIPT_DIR/variables.sh" # loads used variables. requires constants and parameters.
. "$SCRIPT_DIR/errors.sh" # loads the error messages.
. "$SCRIPT_DIR/functions.sh" # loads the functions used.
. "$SCRIPT_DIR/protocols.sh" # loads the instalation flows for each kind of node used.

# Read parameters from command line
read_parameters "$@"

# enabling error handling
trap execution_error ERR

# if we only want to generate .pem and .cert from a .crt file, we ignore everything else.
if [ -z "$CRT_FILE" && -z "$PRIVATE_KEY" ]; then
  # generate files from .crt and exit
  generate_file_protocol $PEM_AND_CERT_FILES
  # all done
  exit 0
fi

validate_domain "$DOMAIN"

# if we only want to generate a .cfg template file, ignore everything else.
validate_template_flag "$TEMPLATE"
if [ "$TEMPLATE" -eq 1 ]; then
  # generate configuration template file and exit
  generate_file_protocol $CONFIGURATION_FILE_TEMPLATE
  # all done
  exit 0;
fi

validate_self_signed $SELF_SIGNED
validate_configuration_file $CONFIGURATION_FILE

# decide which protocols to follow
if [ "$SELF_SIGNED" -eq 1 ]; then
  self_signed_protocol
elif [ "$SELF_SIGNED" -eq 0 ]; then
  certificate_request_protocol
else
  execution_error "$ERR_UP"
fi

# all done
exit 0