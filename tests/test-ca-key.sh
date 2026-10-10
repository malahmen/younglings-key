#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# tests/test-ca-key.sh — YK-7's remainder: where the CA private key lives, how
# it is protected, and how long the two kinds of certificate last.
#
# Nothing here needs privileges or a trust store; every run works in a
# temporary directory. stdin is closed for every invocation, which is part of
# the point: the refusal path for `-E` with no passphrase source only means
# anything if nothing falls back to prompting.
#
# IGNITE=/path/to/ignite.sh tests another copy of the engine.
# -----------------------------------------------------------------------------
set -uo pipefail

ENGINE="${IGNITE:-$(cd "$(dirname "$0")/.." && pwd)/ignite.sh}"
[ -f "$ENGINE" ] || { echo "engine not found: $ENGINE" >&2; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "SKIP - openssl not installed" >&2; exit 0; }

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
cd "$W" || exit 1

FAILED=0
ok()  { printf '  PASS  %s\n' "$1"; }
bad() { printf '  FAIL  %s\n' "$1" >&2; FAILED=$((FAILED + 1)); }
check() { local d="$1"; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }
# Colour stripped so assertions match with or without a TTY; stdin closed so a
# regression that prompts fails instead of waiting.
#
# Both streams, combined: the engine sends msg() to stdout and wrn()/oerr() to
# stderr, so a suite watching only one of them asserts on half the output and
# an "it said so" check passes or fails for the wrong reason.
OUTPUT=""; RC=0
run() { OUTPUT="$(bash "$ENGINE" "$@" </dev/null 2>&1 | sed -e 's/\x1b\[[0-9;]*m//g')"; RC=${PIPESTATUS[0]}; }
in_out() { printf '%s' "$OUTPUT" | grep -qE -- "$1"; }
no_out() { ! printf '%s' "$OUTPUT" | grep -qE -- "$1"; }
mode_is() { [ "$(stat -c '%a' "$2" 2>/dev/null || stat -f '%Lp' "$2")" = "$1" ]; }
# openssl verify prints "file: OK" on stdout; the suite only wants the status.
verifies() { openssl verify -CAfile "$1" "$2" >/dev/null 2>&1; }
has_ext() { openssl x509 -in "$1" -noout -text 2>/dev/null | grep -q -- "$2"; }
# A certificate's lifetime in days, from its own notBefore/notAfter.
lifetime_days() {
    local f="$1" nb na
    nb=$(date -u -d "$(openssl x509 -in "$f" -noout -startdate | cut -d= -f2)" +%s 2>/dev/null) || return 1
    na=$(date -u -d "$(openssl x509 -in "$f" -noout -enddate   | cut -d= -f2)" +%s 2>/dev/null) || return 1
    echo $(( (na - nb) / 86400 ))
}
days_is() { [ "$(lifetime_days "$2")" = "$1" ]; }

printf 'correct horse battery staple\n' > pass; chmod 600 pass

echo "--- a new CA puts its key in a 0700 directory, not beside the leaves ---"
run -d one.lan -i '/C=PT/O=T/CN=one.lan' -o plain
check "the run succeeds"                 test "$RC" -eq 0
check "the key is in ca-private/"         test -f plain/ca-private/ca.key
check "the directory is 0700"             mode_is 700 plain/ca-private
check "the key is 0600"                   mode_is 600 plain/ca-private/ca.key
check "nothing is left at the old path"   test ! -e plain/ca.key
# The certificate must NOT move: other tools read it by path, kuat's lan_tls
# role among them.
check "the CA certificate stays put"      test -f plain/ca.crt
check "the leaf was issued"               test -s plain/one.lan.crt
check "and the CA vouches for it"         verifies plain/ca.crt plain/one.lan.crt
check "an unencrypted key is reported"    in_out 'NOT encrypted'
check "and it says how to fix it"         in_out '[-]E'

echo
echo "--- leaf and CA lifetimes are separate ---"
# They shared one value, so a leaf short enough for Apple platforms to accept
# would also have shortened the root — which means re-distributing the anchor.
check "the leaf lasts 398 days"  days_is 398 plain/one.lan.crt
check "the CA lasts 3650 days"   days_is 3650 plain/ca.crt
run -d two.lan -i '/C=PT/O=T/CN=two.lan' -o split -t 30 -c 60
check "-t sets the leaf"  days_is 30 split/two.lan.crt
check "-c sets the CA"    days_is 60 split/ca.crt
run -d bad.lan -i '/C=PT/O=T/CN=bad.lan' -o cbad -c 99999
check "-c past the ceiling is refused"  test "$RC" -eq 1
check "with the range in the message"   in_out '7300'
run -d bad.lan -i '/C=PT/O=T/CN=bad.lan' -o cbad -c abc
check "-c that is not a number is refused" test "$RC" -eq 1

echo
echo "--- -E encrypts a new CA key ---"
run -d enc.lan -i '/C=PT/O=T/CN=enc.lan' -o enc -E -p pass
check "the run succeeds"             test "$RC" -eq 0
check "the key is encrypted"         grep -q 'ENCRYPTED' enc/ca-private/ca.key
check "and still 0600"               mode_is 600 enc/ca-private/ca.key
check "the leaf was issued"          verifies enc/ca.crt enc/enc.lan.crt
check "no warning about encryption"  no_out 'NOT encrypted'
# The half that matters operationally: the CA has to be usable AGAIN, with the
# passphrase, or an encrypted CA is a one-shot CA.
run -d enc2.lan -i '/C=PT/O=T/CN=enc2.lan' -o enc -E -p pass
check "a second leaf from the same CA"  test "$RC" -eq 0
check "and the CA vouches for it too"   verifies enc/ca.crt enc/enc2.lan.crt
check "the CA was reused, not rebuilt"  test "$(grep -c 'BEGIN CERTIFICATE' enc/ca.crt)" = 1

echo
echo "--- the passphrase comes from a file, never from argv ---"
# argv is readable by every process on the machine for as long as openssl runs,
# so the engine must never build a `pass:` argument — only `file:`. Asserted
# against the source, because no behavioural test can see an argv that is
# merely possible.
check "the engine never builds -pass pass:" \
    bash -c '! grep -rn "pass:" "$1"/*.sh' _ "$(cd "$(dirname "$ENGINE")" && pwd)"
YOUNGLINGS_CA_PASSPHRASE_FILE="$W/pass" run -d envp.lan -i '/C=PT/O=T/CN=envp.lan' -o envdir -E
check "YOUNGLINGS_CA_PASSPHRASE_FILE works" test "$RC" -eq 0
check "and the key is encrypted"            grep -q 'ENCRYPTED' envdir/ca-private/ca.key

echo
echo "--- a bad passphrase source is refused BEFORE a key exists ---"
# This is the regression that matters most. The refusal used to be printed from
# inside a command substitution, where execution_error exits only the subshell:
# the caller then ran `openssl genrsa -aes256` with no passphrase argument at
# all, openssl prompted, took the EOF as an empty passphrase, and wrote a
# usable UNENCRYPTED key — after saying it had refused.
run -d x.lan -i '/C=PT/O=T/CN=x.lan' -o noterm -E
check "no passphrase source and no tty is refused" test "$RC" -eq 1
check "and it names the alternatives"              in_out 'YOUNGLINGS_CA_PASSPHRASE_FILE'
check "NO key was written"                         test ! -e noterm/ca-private/ca.key
check "no CA certificate either"                   test ! -e noterm/ca.crt

printf 'secret\n' > loose; chmod 644 loose
run -d x.lan -i '/C=PT/O=T/CN=x.lan' -o loosedir -E -p loose
check "a world-readable passphrase file is refused" test "$RC" -eq 1
check "with the mode in the message"                in_out 'mode 644'
check "and nothing was created"                     test ! -d loosedir

: > empty; chmod 600 empty
run -d x.lan -i '/C=PT/O=T/CN=x.lan' -o emptydir -E -p empty
check "an empty passphrase file is refused" test "$RC" -eq 1
check "and says why that matters"           in_out 'only looks encrypted'

run -d x.lan -i '/C=PT/O=T/CN=x.lan' -o gonedir -E -p nosuchfile
check "a missing passphrase file is refused" test "$RC" -eq 1

printf 'wrong\n' > badpass; chmod 600 badpass
run -d w.lan -i '/C=PT/O=T/CN=w.lan' -o enc -E -p badpass
check "the wrong passphrase fails the signing" test "$RC" -eq 1
check "and no certificate is written"          test ! -e enc/w.lan.crt

echo
echo "--- a key at the old path keeps working, and -R moves it ---"
# Regenerating a CA because its key "went missing" would invalidate every
# certificate already trusted, so the old location is reused, not ignored.
mkdir -p legacy
cp plain/ca.crt legacy/ca.crt
cp plain/ca-private/ca.key legacy/ca.key
run -d old.lan -i '/C=PT/O=T/CN=old.lan' -o legacy
check "the legacy key is reused"        test "$RC" -eq 0
check "no new CA was built"             cmp -s plain/ca.crt legacy/ca.crt
check "the leaf verifies against it"    verifies legacy/ca.crt legacy/old.lan.crt
check "and the location is reported"    in_out 'sits beside the leaves'
check "with the command to fix it"      in_out '[-]R'
check "but it was NOT moved silently"   test -f legacy/ca.key

run -R -o legacy
check "-R succeeds"                    test "$RC" -eq 0
check "the key is now protected"       test -f legacy/ca-private/ca.key
check "the directory is 0700"          mode_is 700 legacy/ca-private
check "the key is 0600"                mode_is 600 legacy/ca-private/ca.key
check "no copy is left behind"         test ! -e legacy/ca.key
check "the certificate did not move"   test -f legacy/ca.crt
run -d after.lan -i '/C=PT/O=T/CN=after.lan' -o legacy
check "issuing still works after -R"   test "$RC" -eq 0
check "against the same CA"            verifies legacy/ca.crt legacy/after.lan.crt
check "and the warning is gone"        no_out 'sits beside the leaves'

run -R -o legacy
check "-R twice is harmless"           test "$RC" -eq 0
check "and says it is already done"    in_out 'already protected'
run -R -o nowhere
check "-R with no CA is an error"      test "$RC" -eq 1
check "naming the file it wanted"      in_out 'No CA key to move'

echo
echo "--- the constraints from YK-3 and -C survive all of this ---"
check "pathlen:0 on the CA"   has_ext plain/ca.crt 'pathlen:0'
check "keyCertSign on the CA" has_ext plain/ca.crt 'Certificate Sign'
run -d nc.lan -i '/C=PT/O=T/CN=nc.lan' -o ncenc -E -p pass -C '.lan,192.168.0.0/16'
check "-C with an encrypted CA"  test "$RC" -eq 0
check "name constraints present" has_ext ncenc/ca.crt 'Name Constraints'
check "and the leaf still verifies" verifies ncenc/ca.crt ncenc/nc.lan.crt

echo
if [ "$FAILED" -ne 0 ]; then echo "test-ca-key: ${FAILED} check(s) failed" >&2; exit 1; fi
echo "test-ca-key: all checks passed"
