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

echo
if [ "$FAILED" -gt 0 ]; then echo "${FAILED} assertion(s) failed" >&2; exit 1; fi
echo "all assertions passed"
