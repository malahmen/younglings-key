#!/usr/bin/env bash
# Runs every tests/test-*.sh. Non-zero exit if any fails.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
rc=0
for t in test-*.sh; do
    if bash "$t" >/tmp/yk-$t.log 2>&1; then
        printf 'PASS  %s\n' "$t"
    else
        printf 'FAIL  %s\n' "$t" >&2
        sed 's/^/      /' /tmp/yk-$t.log >&2
        rc=1
    fi
    rm -f /tmp/yk-$t.log
done
[ "$rc" -eq 0 ] && echo "all test files passed"
exit "$rc"
