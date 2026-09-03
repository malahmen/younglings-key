# Generation flows for ignite.sh. Sourced — not run directly.
# All output goes under $CERTIFICATES_PATH (set in variables.sh, relative to CWD).

# ---- Self-signed certificate --------------------------------------------------

self_signed_protocol() {
    if [ -n "$CONFIGURATION_FILE" ]; then
        self_signed_protocol_configured
    else
        self_signed_protocol_subject
    fi
}

# Self-signed, CSR driven by an openssl config file.
self_signed_protocol_configured() {
    execute mkdir -p "$CERTIFICATES_PATH"
    _build_ca
    execute openssl genrsa -out "$CERTIFICATES_PATH/$DOMAIN.key" "$NUMBITS"
    execute openssl req -sha512 -new \
        -key "$CERTIFICATES_PATH/$DOMAIN.key" \
        -out "$CERTIFICATES_PATH/$DOMAIN.csr" \
        -config "$CONFIGURATION_FILE"
    _sign_with_ca
    _emit_cert_and_pem
}

# Self-signed, CSR driven by a subject string.
self_signed_protocol_subject() {
    execute mkdir -p "$CERTIFICATES_PATH"
    _build_ca
    execute openssl genrsa -out "$CERTIFICATES_PATH/$DOMAIN.key" "$NUMBITS"
    execute openssl req -sha512 -new -subj "$SUBJECT" \
        -key "$CERTIFICATES_PATH/$DOMAIN.key" \
        -out "$CERTIFICATES_PATH/$DOMAIN.csr"
    _sign_with_ca
    _emit_cert_and_pem
}

# ---- Certificate signing request (no signing) ---------------------------------

certificate_request_protocol() {
    if [ -n "$CONFIGURATION_FILE" ]; then
        certificate_request_protocol_configured
    else
        certificate_request_protocol_subject
    fi
}

certificate_request_protocol_subject() {
    execute mkdir -p "$CERTIFICATES_PATH"
    execute openssl genrsa -out "$CERTIFICATES_PATH/$DOMAIN.key" "$NUMBITS"
    execute openssl req -sha512 -new -subj "$SUBJECT" \
        -key "$CERTIFICATES_PATH/$DOMAIN.key" \
        -out "$CERTIFICATES_PATH/$DOMAIN.csr"
    execute openssl req -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.csr"
    msg "Generated CSR: $CERTIFICATES_PATH/$DOMAIN.csr (and key $DOMAIN.key)"
}

certificate_request_protocol_configured() {
    execute mkdir -p "$CERTIFICATES_PATH"
    execute openssl genrsa -out "$CERTIFICATES_PATH/$DOMAIN.key" "$NUMBITS"
    execute openssl req -sha512 -new \
        -key "$CERTIFICATES_PATH/$DOMAIN.key" \
        -out "$CERTIFICATES_PATH/$DOMAIN.csr" \
        -config "$CONFIGURATION_FILE"
    execute openssl req -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.csr"
    msg "Generated CSR: $CERTIFICATES_PATH/$DOMAIN.csr (and key $DOMAIN.key)"
}

# ---- Shared steps -------------------------------------------------------------

_build_ca() {
    execute openssl genrsa -out "$CERTIFICATES_PATH/ca.key" "$NUMBITS"
    execute openssl req -x509 -new -nodes -sha512 -days "$DURATION" \
        -subj "$SUBJECT_CA" \
        -key "$CERTIFICATES_PATH/ca.key" \
        -out "$CERTIFICATES_PATH/ca.crt"
}

_sign_with_ca() {
    execute openssl req -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.csr"
    execute openssl x509 -req -sha512 -days "$DURATION" \
        -CA "$CERTIFICATES_PATH/ca.crt" -CAkey "$CERTIFICATES_PATH/ca.key" -CAcreateserial \
        -in "$CERTIFICATES_PATH/$DOMAIN.csr" \
        -out "$CERTIFICATES_PATH/$DOMAIN.crt"
    execute openssl x509 -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.crt"
}

# From $DOMAIN.crt (+ .key) produce the .cert and .pem convenience files.
_emit_cert_and_pem() {
    execute openssl x509 -inform PEM -in "$CERTIFICATES_PATH/$DOMAIN.crt" \
        -out "$CERTIFICATES_PATH/$DOMAIN.cert"
    execute cat "$CERTIFICATES_PATH/$DOMAIN.key" "$CERTIFICATES_PATH/$DOMAIN.crt" \
        > "$CERTIFICATES_PATH/$DOMAIN.pem"
    msg "Generated: $DOMAIN.crt, $DOMAIN.cert, $DOMAIN.pem in $CERTIFICATES_PATH/"
}

# ---- File conversions ---------------------------------------------------------

# Decide which file-generation protocol to run.
generate_file_protocol() {
    local requested="${1:-}"
    if [ "$requested" = "$PEM_AND_CERT_FILES" ]; then
        generate_files_from_crt_protocol
    elif [ "$requested" = "$CONFIGURATION_FILE_TEMPLATE" ]; then
        generate_configuration_file_template_protocol
    else
        execution_error "$ERR_UP"
    fi
}

# Build .cert (always) and .pem (when a key is given) from an existing .crt.
# -r/-k accept a path as given, or a bare name resolved inside ./certificates.
generate_files_from_crt_protocol() {
    execute mkdir -p "$CERTIFICATES_PATH"

    local crt_path="$CRT_FILE"
    [ -f "$crt_path" ] || crt_path="$CERTIFICATES_PATH/$CRT_FILE"
    [ -f "$crt_path" ] || execution_error "$ERR_CRT_FNF"
    # Fail clearly on the wrong file (e.g. a .cfg) instead of dumping openssl's
    # decoder errors when it can't parse a certificate.
    grep -q "BEGIN CERTIFICATE" "$crt_path" || execution_error "$ERR_CRT_NC"

    execute openssl x509 -text -noout -in "$crt_path"
    execute openssl x509 -inform PEM -in "$crt_path" -out "$CERTIFICATES_PATH/$DOMAIN.cert"
    msg "Generated: $CERTIFICATES_PATH/$DOMAIN.cert"

    if [ -n "$PRIVATE_KEY" ]; then
        local key_path="$PRIVATE_KEY"
        [ -f "$key_path" ] || key_path="$CERTIFICATES_PATH/$PRIVATE_KEY"
        [ -f "$key_path" ] || execution_error "$ERR_KEY_FNF"
        grep -q "PRIVATE KEY" "$key_path" || execution_error "$ERR_KEY_NK"
        execute cat "$key_path" "$crt_path" > "$CERTIFICATES_PATH/$DOMAIN.pem"
        msg "Generated: $CERTIFICATES_PATH/$DOMAIN.pem"
    else
        wrn "$ERR_KEY_FNS — skipping .pem (pass -k <key> to include it)."
    fi
}

# Write a ready-to-edit openssl config template for $DOMAIN.
generate_configuration_file_template_protocol() {
    execute mkdir -p "$CERTIFICATES_PATH"
    local out="$CERTIFICATES_PATH/$DOMAIN.cfg"
    cat > "$out" <<-EOF
	[ req ]
	default_bits        = $NUMBITS
	default_md          = sha256
	prompt              = no
	distinguished_name  = req_distinguished_name
	req_extensions      = req_ext
	x509_extensions     = v3_ca

	[ req_distinguished_name ]
	C  = US
	ST = State
	L  = City
	O  = Organization
	CN = $DOMAIN

	[ req_ext ]
	subjectAltName = @alt_names

	[ v3_ca ]
	subjectAltName = @alt_names

	[ alt_names ]
	DNS.1 = $DOMAIN
	DNS.2 = www.$DOMAIN
	# Add more DNS.3, DNS.4, ... or IP.1, IP.2, ... as needed.
	EOF
    msg "Template written: $out"
}
