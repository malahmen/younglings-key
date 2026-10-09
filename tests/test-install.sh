#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# tests/test-install.sh — the -o and -I behaviours, with no privileges needed.
#
# Everything here runs as an ordinary user against temporary directories. The
# successful install itself needs root and a real trust store, so it is checked
# in a container instead (see README); what is asserted here is the part that
# protects you from a mistake: what -I REFUSES, and that -o is honoured.
#
# IGNITE=/path/to/ignite.sh tests another copy of the engine.
# -----------------------------------------------------------------------------
set -uo pipefail

ENGINE="${IGNITE:-$(cd "$(dirname "$0")/.." && pwd)/ignite.sh}"
[ -f "$ENGINE" ] || { echo "engine not found: $ENGINE" >&2; exit 1; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT

# NOTHING HERE MAY TOUCH A REAL TRUST STORE.
#
# It used to. The -T acceptance loop below ran `-I ca.crt -T nss` (and -T all)
# as the ordinary user to see whether the flag parsed — and that performs the
# whole install, so every run added a throwaway CA to every NSS database on
# the machine and then deleted its key. On this developer's laptop that is
# five databases: ~/.pki/nssdb plus four Flatpak browsers.
#
# Two defences. First, the flag checks call the validators directly instead of
# running an install (see below). Second, this: shadowing certutil and the
# trust-update commands with hard failures, so a future edit that reintroduces
# a real install fails the suite instead of modifying the machine.
export PATH="$W/no-touch:$PATH"
mkdir -p "$W/no-touch"
for forbidden in certutil update-ca-trust update-ca-certificates trust; do
    cat > "$W/no-touch/$forbidden" <<'GUARD'
#!/bin/sh
echo "TEST GUARD: $(basename "$0") must not be called by this suite - it writes to a real trust store" >&2
exit 97
GUARD
    chmod +x "$W/no-touch/$forbidden"
done
OUT="$W/certs"
FAILED=0

ok()   { printf '  PASS  %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1" >&2; FAILED=$((FAILED + 1)); }
# Strip colour so assertions match regardless of whether a TTY is attached.
run()  { bash "$ENGINE" "$@" 2>&1 | sed -e 's/\x1b\[[0-9;]*m//g'; }

# --- -o is honoured ----------------------------------------------------------
# The regression this guards: variables.sh computes CERTIFICATES_PATH when it is
# sourced, which is BEFORE the flags are parsed. Without resolve_paths(), -o
# parses cleanly, changes nothing, and the key lands in ./certificates — telling
# the caller it went somewhere it did not.
cd "$W"
run -d 'test.lan' -o "$OUT" -i '/C=PT/O=T/CN=test.lan' >/dev/null
if [ -s "$OUT/test.lan.crt" ]; then ok "-o writes into the chosen directory"
else bad "-o did not produce $OUT/test.lan.crt"; fi
if [ -d "$W/certificates" ]; then bad "-o was ignored: ./certificates was created"
else ok "-o does not also write ./certificates"; fi

# --- the generated certificate is CA-signed, with a SAN ----------------------
if openssl verify -CAfile "$OUT/ca.crt" "$OUT/test.lan.crt" >/dev/null 2>&1
then ok "leaf verifies against the generated CA"
else bad "leaf does not verify against the CA"; fi
if openssl x509 -noout -ext subjectAltName -in "$OUT/test.lan.crt" 2>/dev/null | grep -q 'test.lan'
then ok "leaf carries a subjectAltName"
else bad "leaf has no SAN - modern clients ignore CN"; fi

# --- -I refuses everything that is not a certificate -------------------------
# The CSR case is the one that matters: "-----BEGIN CERTIFICATE REQUEST-----"
# contains the substring "BEGIN CERTIFICATE", so a text match accepts it and a
# CSR gets installed as a trust anchor. openssl x509 is what rejects it.
for pair in "test.lan.csr:a CSR" "test.lan.key:a private key" "test.lan.cfg:a config file"; do
    f="$OUT/${pair%%:*}"; label="${pair##*:}"
    [ -e "$f" ] || continue
    out="$(run -I "$f")"
    if printf '%s' "$out" | grep -q 'Installing into'; then
        bad "-I accepted ${label} - it would be installed as a trust anchor"
    else
        ok "-I refuses ${label}"
    fi
done

out="$(run -I "$W/does-not-exist.crt")"
if printf '%s' "$out" | grep -q 'not found'; then ok "-I refuses a missing file"
else bad "-I did not report a missing file"; fi

# --- -I never elevates on its own --------------------------------------------
# A tool that silently acquires root to change what the machine trusts is the
# one place that is least acceptable. It must print the commands and stop.
if [ "$(id -u)" -ne 0 ]; then
    out="$(run -I "$OUT/ca.crt")"
    if printf '%s' "$out" | grep -q 'needs root'; then ok "-I refuses to elevate"
    else bad "-I did not refuse as non-root"; fi
    if printf '%s' "$out" | grep -q 'sudo install -m 0644'; then ok "-I prints the exact commands"
    else bad "-I did not print the commands to run"; fi
    if printf '%s' "$out" | grep -q 'CN *= *Younglings Root CA'; then ok "-I shows whose certificate it is"
    else bad "-I did not show the subject before installing"; fi
else
    printf '  SKIP  non-root assertions (running as root)\n'
fi

# --- the leaf states what it is (Y3) -----------------------------------------
# Leaves used to carry no basicConstraints, no keyUsage and no EKU at all.
leaf_ext="$(openssl x509 -in "$OUT/test.lan.crt" -noout -text)"
for want in 'CA:FALSE' 'Key Usage' 'TLS Web Server Authentication'; do
    if printf '%s' "$leaf_ext" | grep -q "$want"; then ok "the leaf carries ${want}"
    else bad "the leaf is missing ${want}"; fi
done
if openssl verify -CAfile "$OUT/ca.crt" -purpose sslserver "$OUT/test.lan.crt" >/dev/null 2>&1
then ok "the leaf still verifies for sslserver"
else bad "the leaf no longer verifies for sslserver"; fi
# A CSR that declares its own EKU must keep it: an -extfile silently wins over
# the CSR, so the defaults are only filled in where the CSR said nothing.
cfg="$W/eku.cfg"
cat > "$cfg" <<'CFG'
[ req ]
prompt = no
distinguished_name = dn
req_extensions = ext
[ dn ]
CN = code.lan
[ ext ]
subjectAltName = DNS:code.lan
extendedKeyUsage = codeSigning
CFG
run -d 'code.lan' -o "$W/eku" -f "$cfg" >/dev/null 2>&1
if openssl x509 -in "$W/eku/code.lan.crt" -noout -ext extendedKeyUsage 2>/dev/null | grep -q 'Code Signing'
then ok "a CSR's own EKU is not overridden"
else bad "a CSR's own EKU was overridden"; fi

# --- -U is validated like -I (YK-6) ------------------------------------------
# The removal itself needs root and a real store, so only the refusals are
# asserted here; the rest is covered by the engine's own harness.
out="$(run -U -I "$OUT/ca.crt" -T bogus)"
if printf '%s' "$out" | grep -q 'Invalid install target'; then ok "-U validates -T"
else bad "-U accepted -T bogus"; fi
out="$(run -U -I "$OUT/ca.crt" -N ../escape.crt -T system)"
if printf '%s' "$out" | grep -q 'Invalid -N name'; then ok "-U validates -N"
else bad "-U accepted a path in -N"; fi
out="$(run -U -I "$OUT/ca.crt" -T system)"
if printf '%s' "$out" | grep -qE 'Not installed in the system store|needs root'; then ok "-U -T system reaches the uninstall"
else bad "-U -T system did not reach the uninstall: ${out}"; fi

# --- -T validation -----------------------------------------------------------
# Rejection can still go through the engine: it exits at validation, before
# anything is installed.
for bad in bogus "" system,nss; do
    out="$(run -I "$OUT/ca.crt" -T "$bad")"
    if printf '%s' "$out" | grep -q 'Invalid install target'; then
        ok "-T rejects '${bad}'"
    else
        bad "-T accepted '${bad}'"
    fi
done
# ACCEPTANCE calls the validator directly. Running the engine to prove that
# 'nss' parses meant performing the install to find out, which is what put a
# CA into every browser database on the machine.
# shellcheck source=/dev/null
(
    . "$(dirname "$ENGINE")/regex.sh";      . "$(dirname "$ENGINE")/colors.sh"
    . "$(dirname "$ENGINE")/parameters.sh"; . "$(dirname "$ENGINE")/constants.sh"
    . "$(dirname "$ENGINE")/variables.sh";  . "$(dirname "$ENGINE")/errors.sh"
    . "$(dirname "$ENGINE")/functions.sh"
    for good in system nss all; do
        if validate_install_target "$good" 2>/dev/null; then echo "ACCEPT:$good"; fi
    done
    # -N lands in a root-owned directory, so it must not carry a path.
    for n in 'ok.crt' 'plain'; do
        if validate_install_name "$n" 2>/dev/null; then echo "NAME_OK:$n"; fi
    done
    for n in '../../etc/ssl/certs/evil.crt' '/etc/pki/evil.crt' 'a/b.crt' '.hidden'; do
        if validate_install_name "$n" 2>/dev/null; then echo "NAME_ACCEPTED:$n"; fi
    done
) > "$W/validators.out" 2>&1
for good in system nss all; do
    if grep -qx "ACCEPT:$good" "$W/validators.out"; then ok "-T accepts '${good}'"
    else bad "-T rejected '${good}'"; fi
done
for n in 'ok.crt' 'plain'; do
    if grep -qx "NAME_OK:$n" "$W/validators.out"; then ok "-N accepts '${n}'"
    else bad "-N rejected the plain name '${n}'"; fi
done
if grep -q 'NAME_ACCEPTED' "$W/validators.out"; then
    bad "-N accepted a path: $(grep NAME_ACCEPTED "$W/validators.out" | tr '\n' ' ')"
else
    ok "-N rejects paths, traversal and dotfiles"
fi

# --- NSS discovery -----------------------------------------------------------
# Only shape is asserted here: a database that exists must be found, and a glob
# that matched nothing must never be returned as a path. Installing into one is
# checked in a container (see README) because it needs certutil.
# shellcheck source=/dev/null
(
    . "$(dirname "$ENGINE")/regex.sh";      . "$(dirname "$ENGINE")/colors.sh"
    . "$(dirname "$ENGINE")/parameters.sh"; . "$(dirname "$ENGINE")/constants.sh"
    . "$(dirname "$ENGINE")/variables.sh";  . "$(dirname "$ENGINE")/errors.sh"
    . "$(dirname "$ENGINE")/functions.sh"
    found=0
    while read -r d; do
        [ -n "$d" ] || continue
        found=$((found + 1))
        # An unexpanded glob would come back containing a '*'.
        case "$d" in *'*'*) echo "GLOB_LEAKED:$d" ;; esac
        [ -f "$d/cert9.db" ] || [ -f "$d/cert8.db" ] || echo "NOT_A_DB:$d"
    done < <(discover_nss_stores)
    echo "COUNT:$found"
) > "$W/nss.out" 2>&1
if grep -q 'GLOB_LEAKED' "$W/nss.out"; then
    bad "discover_nss_stores returned an unexpanded glob"
else
    ok "discover_nss_stores never returns an unexpanded glob"
fi
if grep -q 'NOT_A_DB' "$W/nss.out"; then
    bad "discover_nss_stores returned a directory with no cert db"
else
    ok "discover_nss_stores returns only real databases"
fi

# --- the sudo trap -----------------------------------------------------------
# Under sudo, $HOME is root's. The system store needs root and the NSS stores
# belong to the person at the keyboard, so nss_home must follow $SUDO_USER or
# `sudo ignite -I` populates root's browser profiles and the browsers stay
# exactly as untrusting as before.
h="$(SUDO_USER="$(id -un)" bash -c '
    . '"$(dirname "$ENGINE")"'/regex.sh; . '"$(dirname "$ENGINE")"'/colors.sh
    . '"$(dirname "$ENGINE")"'/parameters.sh; . '"$(dirname "$ENGINE")"'/constants.sh
    . '"$(dirname "$ENGINE")"'/variables.sh; . '"$(dirname "$ENGINE")"'/errors.sh
    . '"$(dirname "$ENGINE")"'/functions.sh
    HOME=/root nss_home')"
if [ "$h" = "$(getent passwd "$(id -un)" | cut -d: -f6)" ]; then
    ok "nss_home follows \$SUDO_USER, not root's HOME"
else
    bad "nss_home returned '${h}' - sudo would populate the wrong user's stores"
fi

echo
if [ "$FAILED" -gt 0 ]; then echo "${FAILED} assertion(s) failed" >&2; exit 1; fi
echo "all assertions passed"
