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
# True when `openssl req` supports -addext (OpenSSL >= 1.1.1, LibreSSL >= 3.1).
_openssl_has_addext() { openssl req -help 2>&1 | grep -q -- '-addext'; }

_build_ca() {
    if [ -f "$CERTIFICATES_PATH/ca.key" ] && [ -f "$CERTIFICATES_PATH/ca.crt" ]; then
        msg "Reusing existing CA: $CERTIFICATES_PATH/ca.crt (delete ca.key and ca.crt to regenerate)"
        return 0
    fi
    execute openssl genrsa -out "$CERTIFICATES_PATH/ca.key" "$NUMBITS"

    # The CA says what it is, explicitly, instead of relying on what each
    # openssl adds by default — and they differ:
    #   OpenSSL 3      basicConstraints critical CA:TRUE, but NO keyUsage
    #   LibreSSL       neither: a v1 certificate with no extensions at all,
    #                  which -I then wrongly reports as "not a CA", and which
    #                  Chrome, macOS and NSS may refuse outright
    # pathlen:0 because this CA signs leaves, never another CA.
    local ca_ext=()
    if _openssl_has_addext; then
        ca_ext=(-addext "basicConstraints = critical, CA:TRUE, pathlen:0"
                -addext "keyUsage = critical, keyCertSign, cRLSign")
    else
        wrn "This openssl has no -addext: the CA will carry whatever extensions"
        wrn "it adds by default, which on LibreSSL is none. Browsers may refuse it."
    fi
    execute openssl req -x509 -new -nodes -sha512 -days "$DURATION" \
        -subj "$SUBJECT_CA" \
        "${ca_ext[@]+${ca_ext[@]}}" \
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

# _write_leaf_extfile <out> <csr> — the extensions a leaf should carry.
#
# Y3: leaves were issued with no basicConstraints, no keyUsage and no EKU at
# all. Nothing in this homelab rejects that — `openssl verify -purpose
# sslserver` and `-purpose sslclient` both pass on the real meksha.lan leaf
# without them — so this is hygiene rather than a repair: a certificate that
# says what it is for cannot be pressed into another role by something less
# forgiving than OpenSSL, and absent-means-anything is a poor default to ship.
#
# serverAuth AND clientAuth, not serverAuth alone: the LAN services this
# issues for include databases that may want the same certificate for client
# authentication, and an EKU that excludes a use the operator then needs is a
# worse failure than one that is slightly broad.
#
# Only extensions the CSR does NOT already declare are written. Measured: an
# -extfile silently WINS over a CSR's own extension, so a config file asking
# for extendedKeyUsage = codeSigning would otherwise have been quietly
# re-issued as serverAuth.
_write_leaf_extfile() {
    local out="${1:?}" csr="${2:?}" txt
    txt="$(openssl req -text -noout -in "$csr" 2>/dev/null || true)"
    : > "$out"
    printf '%s' "$txt" | grep -q 'X509v3 Basic Constraints' \
        || echo 'basicConstraints = critical, CA:FALSE' >> "$out"
    printf '%s' "$txt" | grep -q 'X509v3 Key Usage' \
        || echo 'keyUsage = critical, digitalSignature, keyEncipherment' >> "$out"
    printf '%s' "$txt" | grep -q 'X509v3 Extended Key Usage' \
        || echo 'extendedKeyUsage = serverAuth, clientAuth' >> "$out"
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
    local extf="$CERTIFICATES_PATH/$DOMAIN.ext"
    local ext_opts=()
    if _openssl_copies_extensions; then
        # -copy_extensions carries the CSR's own extensions (the SAN, and
        # anything a -f config file added); the extfile fills in the leaf
        # extensions it did not declare. Verified that the two compose: the
        # CSR's SAN survives alongside the extfile's additions.
        _write_leaf_extfile "$extf" "$CERTIFICATES_PATH/$DOMAIN.csr"
        ext_opts=(-copy_extensions copy)
        # An empty extfile is not worth passing, and openssl need not accept one.
        [ -s "$extf" ] && ext_opts+=(-extfile "$extf")
    else
        # No -copy_extensions here, so the extfile has to carry the SAN too.
        # This path has always dropped any OTHER extension the CSR declared;
        # that is unchanged.
        _write_san_extfile "$extf"
        _write_leaf_extfile "${extf}.leaf" "$CERTIFICATES_PATH/$DOMAIN.csr"
        cat "${extf}.leaf" >> "$extf"
        rm -f "${extf}.leaf"
        ext_opts=(-extfile "$extf")
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

# -----------------------------------------------------------------------------
# Install an existing certificate into this machine's trust store.
#
# For CLIENTS. Servers in a managed fleet should get their anchors from whatever
# configures them (Ansible, cloud-init); doing it by hand there drifts.
#
# Takes an explicit path and searches nowhere. If the certificate is not on the
# machine, the answer is that it cannot be installed — not that some older copy
# in a default directory gets installed instead.
# -----------------------------------------------------------------------------
# _anchor_base — the name to install the certificate AS, without an extension.
#
# -N when given. Otherwise the certificate's own SHA-256 fingerprint, NOT its
# basename: every CA this tool makes is called ca.crt and carries the same
# subject, so the basename silently overwrote any other tool's ca.crt in the
# anchors directory (and, in NSS, replaced whatever already held the nickname
# "ca" — certutil -A replaces by nickname).
#
# Consequence worth knowing: an anchor installed by an older version as
# ca.crt is NOT replaced by this name, it is joined by it. Pass -N ca.crt to
# overwrite that one deliberately.
_anchor_base() {
    if [ -n "${INSTALL_NAME:-}" ]; then
        printf '%s' "${INSTALL_NAME%.*}"
        return 0
    fi
    local fp
    fp="$(openssl x509 -noout -fingerprint -sha256 -in "$INSTALL_FILE" 2>/dev/null \
          | sed 's/.*=//' | tr -d ':' | tr 'A-Z' 'a-z' | cut -c1-8)"
    [ -n "$fp" ] || fp="unknown"
    printf 'younglings-%s' "$fp"
}

# Install into the OpenSSL/p11-kit system store. Needs root.
_install_system_store() {
    detect_trust_store

    local name dest
    # Debian's update-ca-certificates only reads files ending in .crt and says
    # nothing about the ones it skips.
    name="$(_anchor_base).crt"
    dest="$TRUST_ANCHORS/$name"

    # Show the subject before touching anything: the whole point of a trust
    # anchor is that it can vouch for any name, so the caller should see whose
    # certificate they are about to trust.
    msg "Installing into: $dest"
    openssl x509 -noout -subject -issuer -dates -in "$INSTALL_FILE" 1>&2 || true
    if ! openssl x509 -noout -ext basicConstraints -in "$INSTALL_FILE" 2>/dev/null \
            | grep -q 'CA:TRUE'; then
        wrn "This certificate is not a CA (no basicConstraints CA:TRUE). Installing"
        wrn "it trusts exactly this certificate, not anything it signed."
    fi
    # A trust anchor has to be self-signed to be usable as one: an anchor is
    # where verification STOPS, and a certificate signed by someone else
    # cannot be that. Installing a leaf from a chain adds an anchor nothing
    # verifies against and leaves the caller believing the machine now trusts
    # it. Refused rather than warned about, unlike the non-CA case above,
    # which has a real use (pinning one self-signed server certificate).
    if ! openssl verify -CAfile "$INSTALL_FILE" "$INSTALL_FILE" >/dev/null 2>&1; then
        oerr "Refusing to install a certificate that is not self-signed: $INSTALL_FILE"
        wrn "A trust anchor is where verification stops, so it must verify against"
        wrn "itself. Install the CA that signed this certificate instead."
        exit 1
    fi

    # Never elevates on its own. Trust anchors are the one thing where a tool
    # silently acquiring root is least welcome, so when this is not root it
    # prints the two commands and stops.
    if [ "$(id -u)" -ne 0 ]; then
        oerr "$ERR_INST_ROOT"
        printf '\n  sudo install -m 0644 %s %s\n  sudo %s\n\n' \
            "$INSTALL_FILE" "$dest" "$TRUST_UPDATE" 1>&2
        exit 1
    fi

    execute install -m 0644 "$INSTALL_FILE" "$dest"
    execute "$TRUST_UPDATE"

    # Verify rather than assume. `openssl verify` with no -CAfile uses the
    # system store, so a self-signed CA that is now trusted verifies against
    # itself; before the install it does not. This is the check that the copy
    # and the update actually took effect.
    if openssl verify "$INSTALL_FILE" >/dev/null 2>&1; then
        msg "Installed and trusted: $dest"
    else
        # Undone, not left behind. The copy is already in the anchors
        # directory and the trust update has already run, so a bare error
        # here left the machine in the state the caller was told had failed —
        # a file in a root-owned trust directory that nothing reports and
        # that the next run names differently.
        wrn "Verification failed — removing $dest and re-running $TRUST_UPDATE"
        rm -f "$dest"
        "$TRUST_UPDATE" >/dev/null 2>&1 || wrn "$TRUST_UPDATE failed during rollback; run it by hand"
        execution_error "$ERR_INST_VERIFY: $dest (rolled back)"
    fi
}

# certutil against one NSS database, as that database's owner.
#
# Factored out so the write and the read-back cannot disagree about who runs
# them: the read-back used to run as root even when the write dropped to
# $SUDO_USER, and certutil creates lock files beside the database.
_nss_certutil() {
    local owner="$1" store="$2"; shift 2
    if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$owner" certutil -d "sql:$store" "$@"
    else
        certutil -d "sql:$store" "$@"
    fi
}

# Install into every NSS database on this machine.
#
# Separate from the system store because they are genuinely separate trust
# systems: Chromium-family browsers and Firefox read NSS and ignore the OpenSSL
# store entirely, so a correct system install leaves every browser still
# warning — with nothing to say why.
#
# Needs no root: these are the user's own databases. Run under sudo it drops to
# $SUDO_USER, so one invocation can do both halves correctly.
_install_nss_stores() {
    local stores name owner
    mapfile -t stores < <(discover_nss_stores)
    if [ "${#stores[@]}" -eq 0 ]; then
        wrn "No NSS databases found - nothing to do for browsers."
        wrn "That is expected on a server; on a desktop, start the browser once"
        wrn "so it creates its profile, then re-run."
        return 0
    fi

    command -v certutil >/dev/null 2>&1 || {
        oerr "$ERR_CERTUTIL"
        wrn "Install it (nss-tools / libnss3-tools), or on an image-based system"
        wrn "where layering means a reboot, run certutil from a container:"
        printf '\n  podman run --rm -v <nssdb>:/d:Z -v %s:/c.crt:ro,Z \\\n' "$INSTALL_FILE" 1>&2
        printf '    registry.fedoraproject.org/fedora bash -c \\\n' 1>&2
        printf '    "dnf -q -y install nss-tools && certutil -d sql:/d -A -t %s -n NAME -i /c.crt"\n\n' \
            "'$NSS_TRUST_FLAGS'" 1>&2
        return 1
    }

    name="$(_anchor_base)"
    owner="$(nss_user)"

    local failed=0 s
    for s in "${stores[@]}"; do
        # -A is additive and replaces an entry of the same nickname, so this is
        # safe to re-run.
        _nss_certutil "$owner" "$s" -A \
            -t "$NSS_TRUST_FLAGS" -n "$name" -i "$INSTALL_FILE" 2>/dev/null
        # Read it back rather than trusting the exit code: certutil returns 0
        # for a database it could not actually write.
        #
        # Asked for the nickname directly rather than grepping the listing.
        # `certutil -L` opens with the header
        #
        #   Certificate Nickname                     Trust Attributes
        #
        # so `grep -F "$name"` matched "Certifi(ca)te" for the default name —
        # 'ca', taken from ca.crt — and announced "NSS: added" for a database
        # that had received nothing. The read-back existed precisely to catch
        # that, and could not fail.
        if _nss_certutil "$owner" "$s" -L -n "$name" >/dev/null 2>&1; then
            msg "NSS: added to $s"
        else
            wrn "NSS: FAILED for $s"
            failed=$((failed + 1))
        fi
    done

    [ "$failed" -eq 0 ] || return 1
    wrn "Restart the browsers fully - NSS is read at startup, and closing the"
    wrn "window often leaves a background process holding the old state."
    return 0
}

# ---- Uninstall (YK-6) --------------------------------------------------------
#
# The complement of -I, and necessary once -I stopped using the certificate's
# basename (YK-5): an anchor an older version installed as ca.crt is now
# JOINED by younglings-<fingerprint>.crt rather than replaced, so without this
# there was no way to stop trusting either one through the tool. On this
# machine /etc/pki/ca-trust/source/anchors/ holds exactly such a ca.crt.

# _legacy_anchor — the pre-YK-5 path for this certificate, but only when the
# file there IS this certificate.
#
# Identity by CONTENT, not by name: 'ca.crt' is a name anything could have
# written, and removing another tool's trust anchor because it happens to
# share a filename would be worse than leaving ours behind.
_legacy_anchor() {
    local base cur
    base="$(basename "$INSTALL_FILE")"
    case "$base" in *.crt) ;; *) base="${base%.*}.crt" ;; esac
    cur="$(_anchor_base).crt"
    [ "$base" != "$cur" ] || return 1
    [ -f "$TRUST_ANCHORS/$base" ] || return 1
    cmp -s "$INSTALL_FILE" "$TRUST_ANCHORS/$base" || return 1
    printf '%s' "$TRUST_ANCHORS/$base"
}

_uninstall_system_store() {
    detect_trust_store

    local dest legacy="" removed=0
    dest="$TRUST_ANCHORS/$(_anchor_base).crt"
    legacy="$(_legacy_anchor || true)"

    if [ ! -f "$dest" ] && [ -z "$legacy" ]; then
        wrn "Not installed in the system store: $dest"
        return 0
    fi

    msg "Removing from the system trust store:"
    [ -f "$dest" ] && msg "  $dest"
    [ -n "$legacy" ] && msg "  $legacy  (an older version's name; same certificate)"

    # Never elevates on its own — same rule as the install.
    if [ "$(id -u)" -ne 0 ]; then
        oerr "$ERR_UNINST_ROOT"
        [ -f "$dest" ] && printf '\n  sudo rm -f %s\n' "$dest" 1>&2
        [ -n "$legacy" ] && printf '  sudo rm -f %s\n' "$legacy" 1>&2
        printf '  sudo %s\n\n' "$TRUST_UPDATE" 1>&2
        exit 1
    fi

    [ -f "$dest" ] && { execute rm -f "$dest"; removed=$((removed + 1)); }
    [ -n "$legacy" ] && { execute rm -f "$legacy"; removed=$((removed + 1)); }
    execute "$TRUST_UPDATE"

    # Verified, not assumed — the mirror of the install's check. -I refuses
    # anything that is not self-signed (YK-4), so everything this can be asked
    # to remove verifies against the system store while it is trusted, and
    # must stop doing so once it is gone.
    if openssl verify "$INSTALL_FILE" >/dev/null 2>&1; then
        wrn "Removed ${removed} file(s) and ran $TRUST_UPDATE, but the certificate is STILL trusted."
        wrn "Another copy is installed under a name this cannot recognise, or another"
        wrn "anchor on this machine signs it. Look in $TRUST_ANCHORS."
        return 1
    fi
    msg "Removed ${removed} file(s); no longer trusted."
}

_uninstall_nss_stores() {
    local stores name owner failed=0 s
    mapfile -t stores < <(discover_nss_stores)
    if [ "${#stores[@]}" -eq 0 ]; then
        wrn "No NSS databases found - nothing to do for browsers."
        return 0
    fi
    command -v certutil >/dev/null 2>&1 || { oerr "$ERR_CERTUTIL"; return 1; }

    name="$(_anchor_base)"
    owner="$(nss_user)"
    for s in "${stores[@]}"; do
        if ! _nss_certutil "$owner" "$s" -L -n "$name" >/dev/null 2>&1; then
            msg "NSS: $name not present in $s"
            continue
        fi
        # -D deletes by nickname.
        _nss_certutil "$owner" "$s" -D -n "$name" 2>/dev/null
        # Read back rather than trust the exit code — the same reason the
        # install reads back (certutil returns 0 for a database it could not
        # write), and the same question asked the same way.
        if _nss_certutil "$owner" "$s" -L -n "$name" >/dev/null 2>&1; then
            wrn "NSS: FAILED to remove $name from $s"
            failed=$((failed + 1))
        else
            msg "NSS: removed $name from $s"
        fi
    done

    [ "$failed" -eq 0 ] || return 1
    wrn "Restart the browsers fully - NSS is read at startup, and closing the"
    wrn "window often leaves a background process holding the old state."
    return 0
}

# Dispatcher for -U, selected by -T. Mirrors install_certificate_protocol.
uninstall_certificate_protocol() {
    validate_install_file "$INSTALL_FILE"
    validate_install_target "$INSTALL_TARGET"
    validate_install_name "${INSTALL_NAME:-}"

    # Shown before anything is removed, for the same reason the install shows
    # it: the operator should see whose trust they are about to withdraw.
    msg "Certificate:"
    openssl x509 -noout -subject -issuer -dates -in "$INSTALL_FILE" 1>&2 || true

    local rc=0
    case "$INSTALL_TARGET" in
        system) _uninstall_system_store || rc=1 ;;
        nss)    _uninstall_nss_stores   || rc=1 ;;
        all)
            # NSS first here, the reverse of the install: the system store is
            # the one that needs root and may stop to ask for it, and a
            # browser left trusting a certificate the system no longer does
            # is the more surprising half to leave behind.
            _uninstall_nss_stores   || rc=1
            _uninstall_system_store || rc=1
            ;;
    esac
    return $rc
}

# Dispatcher for -I, selected by -T.
install_certificate_protocol() {
    validate_install_file "$INSTALL_FILE"
    validate_install_target "$INSTALL_TARGET"
    validate_install_name "${INSTALL_NAME:-}"

    local rc=0
    case "$INSTALL_TARGET" in
        system) _install_system_store ;;
        nss)    _install_nss_stores || rc=1 ;;
        all)
            # System first: it needs root and may stop to ask for it, and there
            # is no point populating browsers for a machine that will not trust
            # the certificate itself.
            _install_system_store
            _install_nss_stores || rc=1
            ;;
    esac
    return "$rc"
}
