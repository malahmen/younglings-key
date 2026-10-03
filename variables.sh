# Derived variables. Sourced after constants.sh + parameters.sh.

# Output directory for generated files — relative to the current working dir,
# so ignite.sh never writes into its own (possibly cached/cloned) install dir.
# -o wins when given, so the caller decides where keys land rather than
# inheriting whatever directory it happened to be run from. A private key
# written somewhere the caller did not choose is a key they will not know to
# protect or to delete.
CERTIFICATES_PATH="${OUTPUT_DIR:-$CERTIFICATES_DIR}"
