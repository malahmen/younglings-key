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
        -addext "subjectAltName=$(_san_for_domain)" \
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
        -addext "subjectAltName=$(_san_for_domain)" \
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

# Create the CA once; later runs sign with it so already-trusted certs stay
# valid. Delete ca.key and ca.crt to get a fresh CA.
_build_ca() {
    if [ -f "$CERTIFICATES_PATH/ca.key" ] && [ -f "$CERTIFICATES_PATH/ca.crt" ]; then
        msg "Reusing existing CA: $CERTIFICATES_PATH/ca.crt (delete ca.key and ca.crt to regenerate)"
        return 0
    fi
    execute openssl genrsa -out "$CERTIFICATES_PATH/ca.key" "$NUMBITS"
    execute openssl req -x509 -new -nodes -sha512 -days "$DURATION" \
        -subj "$SUBJECT_CA" \
        -key "$CERTIFICATES_PATH/ca.key" \
        -out "$CERTIFICATES_PATH/ca.crt"
}

# SAN entry used when the CSR is built from a subject string (-i): an IPv4
# address must be an IP: entry, anything else is DNS:.
_san_for_domain() {
    if is_ipv4 "$DOMAIN"; then printf 'IP:%s' "$DOMAIN"; else printf 'DNS:%s' "$DOMAIN"; fi
}

# True when `openssl x509 -req` supports -copy_extensions (OpenSSL >= 3.0;
# LibreSSL and OpenSSL 1.x do not).
_openssl_copies_extensions() {
    local name major
    read -r name major _ < <(openssl version)
    [ "$name" = "OpenSSL" ] && [ "${major%%.*}" -ge 3 ]
}

# Write an -extfile carrying the CSR's SAN (or the entry derived from -d when it has none).
_write_san_extfile() {
    local out="${1:?}" san
    san=$(openssl req -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.csr" \
        | grep -A1 'Subject Alternative Name' | tail -n 1 | tr -d ' ' || true)
    [ -n "$san" ] || san=$(_san_for_domain)
    printf 'subjectAltName = %s\n' "$san" > "$out"
}

# Sign the CSR with the CA. By default `openssl x509 -req` drops the CSR's
# extensions, so the SAN is carried over explicitly: -copy_extensions on
# OpenSSL 3, an -extfile built from the CSR otherwise.
_sign_with_ca() {
    execute openssl req -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.csr"
    local ext_opts=(-copy_extensions copy)
    if ! _openssl_copies_extensions; then
        _write_san_extfile "$CERTIFICATES_PATH/$DOMAIN.ext"
        ext_opts=(-extfile "$CERTIFICATES_PATH/$DOMAIN.ext")
    fi
    execute openssl x509 -req -sha512 -days "$DURATION" "${ext_opts[@]}" \
        -CA "$CERTIFICATES_PATH/ca.crt" -CAkey "$CERTIFICATES_PATH/ca.key" -CAcreateserial \
        -in "$CERTIFICATES_PATH/$DOMAIN.csr" \
        -out "$CERTIFICATES_PATH/$DOMAIN.crt"
    rm -f "$CERTIFICATES_PATH/$DOMAIN.ext"
    execute openssl x509 -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.crt"
}

# From $DOMAIN.crt (+ .key) produce the .cert and .pem convenience files.
_emit_cert_and_pem() {
    execute openssl x509 -inform PEM -in "$CERTIFICATES_PATH/$DOMAIN.crt" \
        -out "$CERTIFICATES_PATH/$DOMAIN.cert"
    _write_pem "$CERTIFICATES_PATH/$DOMAIN.key" "$CERTIFICATES_PATH/$DOMAIN.crt" \
        "$CERTIFICATES_PATH/$DOMAIN.pem"
    msg "Generated: $DOMAIN.crt, $DOMAIN.cert, $DOMAIN.pem in $CERTIFICATES_PATH/"
}

# Bundle key + crt into a .pem. It carries the private key, so it must be 0600:
# umask covers creation, chmod covers a .pem left behind by an earlier run.
_write_pem() {
    local key="${1:?}" crt="${2:?}" out="${3:?}" old_umask
    old_umask=$(umask)
    umask 077
    execute cat "$key" "$crt" > "$out"
    umask "$old_umask"
    execute chmod 600 "$out"
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
        _write_pem "$key_path" "$crt_path" "$CERTIFICATES_PATH/$DOMAIN.pem"
        msg "Generated: $CERTIFICATES_PATH/$DOMAIN.pem"
    else
        wrn "$ERR_KEY_FNS — skipping .pem (pass -k <key> to include it)."
    fi
}

# Write a ready-to-edit openssl config template for $DOMAIN.
generate_configuration_file_template_protocol() {
    execute mkdir -p "$CERTIFICATES_PATH"
    local out="$CERTIFICATES_PATH/$DOMAIN.cfg" alt_names
    if is_ipv4 "$DOMAIN"; then
        alt_names="IP.1  = $DOMAIN"
    elif [ "${DOMAIN#\*.}" != "$DOMAIN" ]; then          # *.example.com + its apex
        alt_names="DNS.1 = $DOMAIN"$'\n'"DNS.2 = ${DOMAIN#\*.}"
    else
        alt_names="DNS.1 = $DOMAIN"$'\n'"DNS.2 = www.$DOMAIN"
    fi
    cat > "$out" <<-EOF
	[ req ]
	default_bits        = $NUMBITS
	default_md          = sha256
	prompt              = no
	distinguished_name  = req_distinguished_name
	req_extensions      = req_ext

	[ req_distinguished_name ]
	C  = US
	ST = State
	L  = City
	O  = Organization
	CN = $DOMAIN

	# Extensions requested in the CSR; ignite.sh copies them into the signed .crt.
	[ req_ext ]
	subjectAltName = @alt_names

	[ alt_names ]
	$alt_names
	# Add more DNS.n / IP.n entries as needed.
	EOF
    msg "Template written: $out"
}
