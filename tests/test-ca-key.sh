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

FAILED=0; SKIPPED=0
ok()  { printf '  PASS  %s\n' "$1"; }
skip() { printf '  SKIP  %s\n' "$1"; SKIPPED=$((SKIPPED + 1)); }
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
# Here-strings, not `printf | grep -q`: under pipefail grep -q exits on its
# match, printf dies of SIGPIPE writing the rest, and the pipeline fails - so
# in_out failed on output that matched and no_out PASSED on it (17 of 500 runs
# on a 6 KB output; Kamino item 198).
in_out() { grep -qE -- "$1" <<<"$OUTPUT"; }
no_out() { ! grep -qE -- "$1" <<<"$OUTPUT"; }
mode_is() { [ "$(stat -c '%a' "$2" 2>/dev/null || stat -f '%Lp' "$2")" = "$1" ]; }
# openssl verify prints "file: OK" on stdout; the suite only wants the status.
verifies() { openssl verify -CAfile "$1" "$2" >/dev/null 2>&1; }
# The key opens with the passphrase in this file (stdin closed: no prompt).
opens_with() { openssl pkey -in "$1" -passin "file:$2" -noout </dev/null >/dev/null 2>&1; }
has_ext() { grep -q -- "$2" <<<"$(openssl x509 -in "$1" -noout -text 2>/dev/null)"; }
sha() { openssl dgst -sha256 "$1" 2>/dev/null | awk '{print $NF}'; }
# A certificate date as epoch seconds: GNU date, else BSD's (macOS). Fails -
# never prints an empty string that a numeric test would wave through - when
# neither can read it. The leaf-ends-before-its-CA check used to compare two
# empty `date -d` results on macOS, `[ -le ]`, which is true (Kamino 198).
to_epoch() {
    local t
    t=$(date -u -d "$1" +%s 2>/dev/null || date -u -j -f '%b %e %T %Y %Z' "$1" +%s 2>/dev/null) || return 1
    [ -n "$t" ] || return 1
    printf '%s' "$t"
}
cert_date() { to_epoch "$(openssl x509 -in "$2" -noout "-$1" | cut -d= -f2)"; }
HAVE_DATE=0; to_epoch 'Jan  1 00:00:00 2030 GMT' >/dev/null && HAVE_DATE=1
# check, for a check that needs to read certificate dates: skipped, and said
# so, on a system whose date can do neither.
dated() {
    local d="$1"; shift
    if [ "$HAVE_DATE" = 1 ]; then check "$d" "$@"
    else skip "$d (this date reads neither -d nor -j -f)"; fi
}
# A certificate's lifetime in days, from its own notBefore/notAfter.
lifetime_days() {
    local nb na
    nb=$(cert_date startdate "$1") || return 1
    na=$(cert_date enddate "$1") || return 1
    echo $(( (na - nb) / 86400 ))
}
days_is() { [ "$(lifetime_days "$2")" = "$1" ]; }
# ends_by <a.crt> <b.crt> - a's notAfter is no later than b's.
ends_by() {
    local a b
    a=$(cert_date enddate "$1") || return 1
    b=$(cert_date enddate "$2") || return 1
    [ "$a" -le "$b" ]
}

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
dated "the leaf lasts 398 days"  days_is 398 plain/one.lan.crt
dated "the CA lasts 3650 days"   days_is 3650 plain/ca.crt
run -d two.lan -i '/C=PT/O=T/CN=two.lan' -o split -t 30 -c 60
dated "-t sets the leaf"  days_is 30 split/two.lan.crt
dated "-c sets the CA"    days_is 60 split/ca.crt
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
echo "--- a CA with one half missing is refused, never regenerated (Kamino 120) ---"
run -d half.lan -i '/C=PT/O=T/CN=half.lan' -o half
key_before="$(sha half/ca-private/ca.key)"
mv half/ca.crt half/ca.crt.aside
run -d half2.lan -i '/C=PT/O=T/CN=half2.lan' -o half
check "certificate missing: refused"              test "$RC" -ne 0
check "it names both halves"                      in_out 'ca-private/ca.key.*certificate.*ca.crt'
check "the key is untouched"                      test "$(sha half/ca-private/ca.key)" = "$key_before"
check "no certificate was made over the gap"      test ! -e half/ca.crt
check "no leaf was issued"                        test ! -e half/half2.lan.crt
mv half/ca.crt.aside half/ca.crt
crt_before="$(sha half/ca.crt)"
mv half/ca-private/ca.key key.aside
run -d half3.lan -i '/C=PT/O=T/CN=half3.lan' -o half
check "key missing (kept offline): refused"       test "$RC" -ne 0
check "it says to put the key back"               in_out 'put the key back'
check "ca.crt is untouched"                       test "$(sha half/ca.crt)" = "$crt_before"
check "no key was made"                           test ! -e half/ca-private/ca.key
mv key.aside half/ca-private/ca.key
run -d half4.lan -i '/C=PT/O=T/CN=half4.lan' -o half
check "both halves back: the CA is reused"        test "$RC" -eq 0
check "...and the leaf verifies against the old anchor" verifies half/ca.crt half/half4.lan.crt
run -d leg.lan -i '/C=PT/O=T/CN=leg.lan' -o leg
mv leg/ca-private/ca.key leg/ca.key; rmdir leg/ca-private; rm leg/ca.crt
run -d leg2.lan -i '/C=PT/O=T/CN=leg2.lan' -o leg
check "a key at the old path without its certificate: refused" test "$RC" -ne 0
check "...and that key is still there"            test -f leg/ca.key

echo
echo "--- every passphrase route is checked, and a weak one refused (Kamino 121) ---"
printf 'correct horse battery staple\n' > envloose; chmod 644 envloose
# The output directory is NOT named after the passphrase file: it was, so
# mkdir failed and this "refusal" passed whatever the engine did with the
# environment's file (Kamino item 180).
YOUNGLINGS_CA_PASSPHRASE_FILE="$W/envloose" run -d e.lan -i '/C=PT/O=T/CN=e.lan' -o envloosedir -E
check "a world-readable file through the environment: refused" test "$RC" -ne 0
check "...for its mode"                           in_out 'mode 644'
check "...before anything exists"                 test ! -e envloosedir
printf '\n' > onlynewline; chmod 600 onlynewline
run -d n.lan -i '/C=PT/O=T/CN=n.lan' -o nldir -E -p onlynewline
check "a file holding only a newline: refused"    test "$RC" -ne 0
check "...as too short"                           in_out 'shorter than 4'
check "...before any key exists"                  test ! -e nldir/ca-private/ca.key
printf 'abc\n' > abc; chmod 600 abc
run -d a.lan -i '/C=PT/O=T/CN=a.lan' -o abcdir -E -p abc
check "a three-character passphrase: refused"     test "$RC" -ne 0
# Three characters and a CR (a file saved on Windows): the CR is not counted.
printf 'abc\r\n' > crlf; chmod 600 crlf
run -d a.lan -i '/C=PT/O=T/CN=a.lan' -o crlfdir -E -p crlf
check "'abc' with a CRLF ending: refused"         test "$RC" -ne 0
check "...as too short"                           in_out 'shorter than 4'
check "...before anything exists"                 test ! -e crlfdir
YOUNGLINGS_CA_PASSPHRASE_FILE="$W/abc" run -d a.lan -i '/C=PT/O=T/CN=a.lan' -o abcenv -E
check "...through the environment too"            test "$RC" -ne 0
run -d enc3.lan -i '/C=PT/O=T/CN=enc3.lan' -o enc -E -p pass
check "the key -E made does not open without its passphrase" \
    bash -c "! YK_EMPTY_PASS= openssl pkey -in enc/ca-private/ca.key -passin env:YK_EMPTY_PASS -noout 2>/dev/null"
# The removal of a key that opens with an empty passphrase is a defence: the
# validation above means no passphrase source reaches genrsa empty. So the
# failure is forced - an openssl on PATH that encrypts -E's key with an empty
# passphrase whatever it was given - to show the defence is there and works.
REAL_OPENSSL="$(command -v openssl)"
mkdir -p emptyshim
cat > emptyshim/openssl <<SHIM
#!/usr/bin/env bash
case " \$* " in
    *" genrsa "*"-aes256 "*)
        args=(); skip=0
        for a in "\$@"; do
            if [ "\$skip" = 1 ]; then args+=("env:YK_SHIM_EMPTY"); skip=0; continue; fi
            [ "\$a" = "-passout" ] && skip=1
            args+=("\$a")
        done
        export YK_SHIM_EMPTY=""
        exec "$REAL_OPENSSL" "\${args[@]}" ;;
esac
exec "$REAL_OPENSSL" "\$@"
SHIM
chmod +x emptyshim/openssl
PATH="$W/emptyshim:$PATH" run -d ep.lan -i '/C=PT/O=T/CN=ep.lan' -o emptypass -E -p pass
check "a key that opens with an empty passphrase: refused" test "$RC" -ne 0
check "...saying so"                              in_out 'opens with an EMPTY passphrase'
check "...and the key is removed"                 test ! -e emptypass/ca-private/ca.key
check "...before any CA certificate"              test ! -e emptypass/ca.crt

echo
echo "--- a leaf never outlives its CA, and -c on an existing CA is said to do nothing ---"
run -d short.lan -i '/C=PT/O=T/CN=short.lan' -o shortca -c 3 -t 365
check "the run succeeds"                          test "$RC" -eq 0
check "it says the leaf was cut to the CA's days" in_out 'The CA expires in [0-9]+ day'
dated "the leaf ends no later than the CA"        ends_by shortca/short.lan.crt shortca/ca.crt
run -d again.lan -i '/C=PT/O=T/CN=again.lan' -o shortca -c 1000
check "-c on an existing CA warns"                in_out '-c only applies to a CA being created'
run -d again2.lan -i '/C=PT/O=T/CN=again2.lan' -o shortca
check "...and without -c, no such warning"        no_out '-c only applies'

echo
echo "--- a leaf never lands on the CA's files (Kamino 163) ---"
# The domain 'ca' wrote its key over a legacy <out>/ca.key (genrsa -out) and
# its certificate over ca.crt. Every leaf output is checked against every CA
# path, in both layouts, ignoring case; CSR mode (-s 0) has no CA step at all
# and used to exit 0 having replaced the key.
run -d keep.lan -i '/C=PT/O=T/CN=keep.lan' -o newl
mkdir -p legl
cp newl/ca.crt legl/ca.crt; cp newl/ca-private/ca.key legl/ca.key
nk="$(sha newl/ca-private/ca.key)"; nc="$(sha newl/ca.crt)"
lk="$(sha legl/ca.key)";            lc="$(sha legl/ca.crt)"
for d in ca CA Ca; do
    for mode in "-s 1" "-s 0"; do
        # shellcheck disable=SC2086 # $mode is two words on purpose
        run -d "$d" $mode -i "/C=PT/O=T/CN=$d" -o newl
        check "new layout, -d $d $mode: refused"            test "$RC" -ne 0
        check "...naming the CA's file"                      in_out "the CA's"
        # shellcheck disable=SC2086
        run -d "$d" $mode -i "/C=PT/O=T/CN=$d" -o legl
        check "legacy layout, -d $d $mode: refused"         test "$RC" -ne 0
    done
done
cfg_ca="$W/ca.cfg"
printf '[req]\nprompt=no\ndistinguished_name=dn\n[dn]\nCN=ca\n' > "$cfg_ca"
run -d ca -s 0 -f "$cfg_ca" -o legl
check "legacy layout, -d ca -s 0 -f: refused"          test "$RC" -ne 0
check "new layout: the CA key is byte-identical"       test "$(sha newl/ca-private/ca.key)" = "$nk"
check "new layout: ca.crt is byte-identical"           test "$(sha newl/ca.crt)" = "$nc"
check "new layout: nothing at the legacy key path"     test ! -e newl/ca.key
check "legacy layout: the CA key is byte-identical"    test "$(sha legl/ca.key)" = "$lk"
check "legacy layout: ca.crt is byte-identical"        test "$(sha legl/ca.crt)" = "$lc"
check "no leaf working files left"                     bash -c '! ls newl/*.new legl/*.new 2>/dev/null | grep -q .'
run -d ca -i '/C=PT/O=T/CN=ca' -o noca
check "with no CA yet, -d ca: refused"                 test "$RC" -ne 0
check "...before anything is written"                  test ! -e noca
# By identity, not only by name: a leaf file that IS a CA file through a link.
ln -s ca-private/ca.key newl/link.lan.pem
run -d link.lan -i '/C=PT/O=T/CN=link.lan' -o newl
check "a leaf output linked to the CA key: refused"    test "$RC" -ne 0
check "...and the CA key is byte-identical"            test "$(sha newl/ca-private/ca.key)" = "$nk"
rm -f newl/link.lan.pem
# grep matches line by line: a domain with a newline passed when one line did.
mkdir -p "newl/x.lan
"
run -d "x.lan
/../ca" -s 0 -i '/C=PT/O=T/CN=x' -o newl
check "a domain with a newline in it: refused"         test "$RC" -ne 0
check "...as an invalid domain"                        in_out 'Invalid domain'
check "...and the CA key is byte-identical"            test "$(sha newl/ca-private/ca.key)" = "$nk"
run -d keep2.lan -i '/C=PT/O=T/CN=keep2.lan' -o newl
check "an ordinary name is still issued"               verifies newl/ca.crt newl/keep2.lan.crt

echo
echo "--- a refused re-issue changes nothing on disk (Kamino 180) ---"
# The leaf key and CSR were written over the old ones before the signing, so a
# refusal left the NEW key beside the OLD certificate. All of a leaf's files
# are now written as .new and renamed only once the certificate verifies.
leaf_sums() { local f; for f in "$1".key "$1".csr "$1".crt "$1".pem; do sha "$f"; done; }
no_new() { ! ls "$1"/*.new "$1"/*.ext "$1"/*.ext.leaf >/dev/null 2>&1; }
# 1. A SAN outside the CA's name constraints: signed, then refused by verify.
run -d r.lan -i '/C=PT/O=T/CN=r.lan' -o reiss -C '.lan'
before="$(leaf_sums reiss/r.lan)"
cfg_out="$W/out.cfg"
printf '[req]\nprompt=no\ndistinguished_name=dn\nreq_extensions=ext\n[dn]\nCN=r.lan\n[ext]\nsubjectAltName=DNS:r.example.com\n' > "$cfg_out"
run -d r.lan -f "$cfg_out" -o reiss
check "re-issue outside the constraints: refused"      test "$RC" -ne 0
check "...key, CSR, certificate and .pem unchanged"    test "$(leaf_sums reiss/r.lan)" = "$before"
check "...and the pair still matches"                  test "$(openssl pkey -in reiss/r.lan.key -pubout | sha /dev/stdin)" = "$(openssl x509 -in reiss/r.lan.crt -noout -pubkey | sha /dev/stdin)"
check "...no working files left"                       no_new reiss
# 2. The wrong CA passphrase.
run -d w2.lan -i '/C=PT/O=T/CN=w2.lan' -o enc -E -p pass
before="$(leaf_sums enc/w2.lan)"
run -d w2.lan -i '/C=PT/O=T/CN=w2.lan' -o enc -E -p badpass
check "re-issue with the wrong passphrase: refused"    test "$RC" -ne 0
check "...key, CSR, certificate and .pem unchanged"    test "$(leaf_sums enc/w2.lan)" = "$before"
check "...no working files left"                       no_new enc
# 3. An expired CA: the same key, re-certified for a day in 2020 (openssl ca,
# because req -x509 on OpenSSL 3.0 cannot set a date in the past).
run -d x2.lan -i '/C=PT/O=T/CN=x2.lan' -o expca
before="$(leaf_sums expca/x2.lan)"
mkdir -p oldca; : > oldca/index; echo 01 > oldca/serial
printf '[ca]\ndefault_ca=c\n[c]\ndatabase=oldca/index\nnew_certs_dir=oldca\nserial=oldca/serial\ndefault_md=sha256\npolicy=p\n[p]\ncommonName=supplied\n' > oldca/cfg
openssl req -new -key expca/ca-private/ca.key -subj '/CN=old' -out oldca/req 2>/dev/null
openssl ca -batch -notext -config oldca/cfg -selfsign -keyfile expca/ca-private/ca.key \
    -startdate 20200101000000Z -enddate 20200102000000Z -in oldca/req -out expca/ca.crt >/dev/null 2>&1
run -d x2.lan -i '/C=PT/O=T/CN=x2.lan' -o expca
check "re-issue from an expired CA: refused"           test "$RC" -ne 0
check "...as expired"                                  in_out 'has expired'
check "...key, CSR, certificate and .pem unchanged"    test "$(leaf_sums expca/x2.lan)" = "$before"
check "...no working files left"                       no_new expca
# 4. CSR mode, with a config file openssl rejects.
run -d c.lan -s 0 -i '/C=PT/O=T/CN=c.lan' -o csr
k="$(sha csr/c.lan.key)"; c="$(sha csr/c.lan.csr)"
printf '[req]\ndistinguished_name=nosuchsection\nprompt=no\n' > "$W/broken.cfg"
run -d c.lan -s 0 -f "$W/broken.cfg" -o csr
check "a CSR openssl refuses: the run fails"           test "$RC" -ne 0
check "...and the previous key and CSR are unchanged"  test "$(sha csr/c.lan.key)$(sha csr/c.lan.csr)" = "$k$c"
check "...no working files left"                       no_new csr

echo
echo "--- the recommended passphrase set-ups work, and keys are 0600 (Kamino 198) ---"
ln -s "$W/pass" passlink
run -d sl.lan -i '/C=PT/O=T/CN=sl.lan' -o symenc -E -p passlink
check "a symlink to a 0600 passphrase file: accepted"  test "$RC" -eq 0
check "...and the key is encrypted"                    grep -q 'ENCRYPTED' symenc/ca-private/ca.key
ln -s "$W/loose" looselink
run -d sl.lan -i '/C=PT/O=T/CN=sl.lan' -o symloose -E -p looselink
check "a symlink to a 0644 file: refused, for its mode" in_out 'mode 644'
run -d pp.lan -i '/C=PT/O=T/CN=pp.lan' -o pipeenc -E -p <(cat "$W/pass")
check "-p <(...) (a pipe): accepted"                   test "$RC" -eq 0
check "...the key is encrypted"                        grep -q 'ENCRYPTED' pipeenc/ca-private/ca.key
check "...with the passphrase's first line"            opens_with pipeenc/ca-private/ca.key "$W/pass"
check "...and the leaf verifies"                       verifies pipeenc/ca.crt pipeenc/pp.lan.crt
run -d pp2.lan -i '/C=PT/O=T/CN=pp2.lan' -o pipeenc -p <(cat "$W/pass")
check "a second leaf, the passphrase through a pipe"   verifies pipeenc/ca.crt pipeenc/pp2.lan.crt
mkfifo fifo
# The writer's streams are not the suite's, so a writer left blocked cannot
# hold the caller's pipe open; opening the FIFO read-write afterwards releases
# it whether or not the engine read it.
(cat "$W/pass" > fifo 2>/dev/null </dev/null &) >/dev/null 2>&1
YOUNGLINGS_CA_PASSPHRASE_FILE="$W/fifo" run -d pf.lan -i '/C=PT/O=T/CN=pf.lan' -o pipeenc
check "a named FIFO through the environment"           verifies pipeenc/ca.crt pipeenc/pf.lan.crt
exec 7<>fifo; exec 7>&-
run -d ps.lan -i '/C=PT/O=T/CN=ps.lan' -o pipeshort -E -p <(printf 'abc\n')
check "a short passphrase through a pipe: refused"     in_out 'shorter than 4'
check "...before anything exists"                      test ! -e pipeshort
check "a leaf key is 0600"                             mode_is 600 plain/one.lan.key
check "its .pem is 0600"                               mode_is 600 plain/one.lan.pem
check "its certificate stays 0644"                     mode_is 644 plain/one.lan.crt
check "and so does ca.crt"                             mode_is 644 plain/ca.crt

echo
if [ "$FAILED" -ne 0 ]; then echo "test-ca-key: ${FAILED} check(s) failed" >&2; exit 1; fi
if [ "$SKIPPED" -ne 0 ]; then echo "test-ca-key: all checks passed, ${SKIPPED} skipped"
else echo "test-ca-key: all checks passed"; fi
