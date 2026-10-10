# younglings-key

[![ci](https://github.com/malahmen/younglings-key/actions/workflows/ci.yml/badge.svg)](https://github.com/malahmen/younglings-key/actions/workflows/ci.yml)

**`ignite.sh` — certificate generation, simplified.**

A small, gum-free, **flag-driven** CLI around `openssl`. It generates certificate
signing requests, self-signed certificates (with their own CA), ready-to-edit
`openssl` config templates, and `.cert`/`.pem` files from an existing `.crt`, and
installs an existing certificate into the machine's trust store — with no
interactive prompts, so it drops straight into scripts and pipelines.

## Capabilities

- **Self-signed certificates** — creates a local CA once and signs certificates with it (great for local dev/testing).
- **Certificate requests (CSR)** — generates a key + CSR to send to a certificate authority.
- **Config templates** — writes an `openssl` `.cfg` template for a domain that you can edit and reuse.
- **Format conversion** — produces `.cert` (and `.pem`, given the key) from an existing `.crt`.
- **Trust-store install** — puts an existing certificate (typically your CA) into this machine's trust stores: the system store *and* every NSS database, which is what browsers actually read.

Output goes where **`-o`** says. With `-o` omitted it falls back to
`./certificates/` in the current directory.

## Requirements

- **`openssl`** — the only hard dependency (checked at start).
- **`bash`** — the script uses `#!/usr/bin/env bash` with strict mode.

Generating needs no elevated privileges and writes only where you point it.
**Installing a trust anchor does need root** — and `ignite.sh` never takes it
for you: run as a normal user it prints the subject of the certificate, then the
exact two commands to run, and exits non-zero.

## Install

```sh
git clone git@github.com:malahmen/younglings-key.git
cd younglings-key
chmod +x ignite.sh
./ignite.sh -h
```

## Usage

```sh
# 1) Write a config template for your domain (then edit ./certificates/example.com.cfg)
./ignite.sh -d example.com -g 1

# 2) Self-signed certificate from a subject string (default mode: -s 1)
./ignite.sh -d example.com \
  -i "/C=PT/O=Acme/CN=example.com" \
  -a "/C=PT/O=Acme/CN=Acme Root CA" -t 365

# 3) Self-signed certificate driven by a config file
./ignite.sh -d example.com \
  -f ./certificates/example.com.cfg \
  -a "/C=PT/O=Acme/CN=Acme Root CA"

# 4) CSR only, to submit to a CA (no signing)
./ignite.sh -d example.com -s 0 -i "/C=PT/O=Acme/CN=example.com"

# 5) Convert an existing .crt into .cert (+ .pem when a key is given)
./ignite.sh -d example.com -r example.com.crt -k example.com.key
```

```sh
# 6) Install a CA into this machine's trust store (needs root)
sudo ./ignite.sh -I ./certificates/ca.crt

# ...and everywhere, write output where you choose rather than ./certificates
./ignite.sh -d example.com -o ~/certs -i '/C=PT/O=Acme/CN=example.com'
```

## Installing a certificate

```sh
./ignite.sh -I /path/to/ca.crt            # shows what it would do, then stops
sudo ./ignite.sh -I /path/to/ca.crt       # system store + every NSS database
./ignite.sh -I /path/to/ca.crt -T nss     # browsers only, no root needed
sudo ./ignite.sh -I /path/to/ca.crt -T system
```

### Removing it again

`-U` takes the same arguments as `-I` and removes exactly what `-I` with those
arguments would have installed:

```sh
sudo ./ignite.sh -U -I /path/to/ca.crt            # system store + every NSS database
./ignite.sh -U -I /path/to/ca.crt -T nss          # browsers only, no root needed
sudo ./ignite.sh -U -I /path/to/ca.crt -T system
```

It also removes the file an **older version** installed under the
certificate's own basename (`ca.crt`), because the default install name is now
derived from the fingerprint and a re-install would otherwise leave that older
copy trusted forever. That file is only removed when it is byte-identical to
the certificate given: `ca.crt` is a name anything could have written, and
removing another tool's anchor because it shares a filename would be worse
than leaving this one behind.

Like the install, it verifies rather than assumes — afterwards the certificate
must no longer verify against the system store. If it still does, a copy is
installed under some other name and that is reported instead of being hidden.

## Protecting the CA key

The CA key is the one secret here that matters: anything that can read it can
issue a certificate for any name the CA is allowed to sign, on every machine
that trusts the anchor. `pathlen:0` and `-C` limit **what it may sign**, which
is not the same as protecting it.

Three things, two of them unconditional:

**It lives in its own `0700` directory.** `<output>/ca-private/ca.key`, mode
`0600`. It used to sit in the output directory beside the leaves — among the
files you copy around — in a directory whose mode nothing set.

The CA **certificate** deliberately does not move: it stays at
`<output>/ca.crt`, because it is public and other things read it by that path.

**Leaf and CA lifetimes are separate.** `-t` is the leaf, default **398 days**;
`-c` is the CA, default **3650**. They used to share one value. 398 and not
3650 because Apple platforms refuse any certificate issued after 2019-07-01
with a lifetime over 825 days, whatever root signed it — so a ten-year leaf was
already unusable on macOS and iOS while looking fine in Chrome and Firefox. 398
is the current public maximum, which keeps one certificate usable everywhere
and makes renewal a habit rather than an event. `-t 3650` is still accepted for
a host nothing Apple will ever talk to.

A root stays long-lived on purpose. Shortening it does not reduce what a leaked
key can do; it only means re-distributing the anchor to every machine and
browser profile that trusts it.

**`-E` encrypts the key** (AES-256), for a CA being created:

```sh
umask 077; printf '%s\n' "$(openssl rand -base64 32)" > ~/ca.pass
./ignite.sh -d 'host.lan' -i '/C=PT/O=Acme/CN=host.lan' -E -p ~/ca.pass
```

The passphrase comes from a **file**, or from `YOUNGLINGS_CA_PASSPHRASE_FILE`,
or from a terminal prompt — never from a flag. There is no option that takes
the passphrase itself, because `argv` is readable by every process on the
machine for as long as `openssl` runs.

That is only worth doing if the passphrase lives somewhere the key does not —
an Ansible vault, a password manager, another host. Both in the same directory
is a speed bump, not a defence.

The refusals are all before anything is written: a passphrase file that is
missing, empty, or readable by others stops the run, and `-E` with no
passphrase source and no terminal to prompt on is an error rather than a
fallback. Without `-E`, an unencrypted CA key is created with a warning saying
exactly what that means.

**Already have a CA?** Its key keeps being used wherever it is, with a warning,
because a CA that regenerated itself because the key "went missing" would
invalidate every certificate already trusted. `-R` moves it deliberately:

```sh
./ignite.sh -R -o ~/.local/share/kuat-pki     # ca.key -> ca-private/ca.key
```

`-R` is a `mv`, not a copy — leaving one behind would defeat the point — and the
CA certificate stays where it was. Encrypting an existing key is a one-liner
the warning prints; this tool will not rewrite a key it did not create.

## Limiting what a CA may issue for

`-C` adds `nameConstraints` to a CA, so a verifier refuses any certificate from
it whose names fall outside the list. It is off by default and applies **only
when a CA is created** — an existing `ca.key`/`ca.crt` pair is reused untouched,
so `-C` can never alter a CA already in a trust store, and certificates already
issued are unaffected either way: the constraint lives on the CA and is checked
at verification time, not baked into a leaf.

```sh
./ignite.sh -d 'host.lan' -C '.lan,192.168.0.0/16'      # DNS suffix + an IP range
```

A `/16` is converted to the dotted netmask this extension actually requires —
openssl refuses a CIDR prefix here, which is the form everyone writes.

Three things are easy to get wrong, so they are worth stating:

- **A single-label name is inside no DNS subtree.** `DNS:.lan` does not permit
  `myhost`. If a certificate needs a bare hostname SAN, DNS cannot be
  constrained.
- **A name form you do not mention stays unconstrained.** Give only DNS
  suffixes and any `IP:` SAN is accepted; add an IP range and every IP SAN must
  fall inside it — including `127.0.0.1`, which is not in RFC 1918.
- **A public domain in the list permits all of it.** Constraining to `.nip.io`
  so that `*.192.168.3.52.nip.io` keeps working also permits
  `anything.1.2.3.4.nip.io`, which is most of the value gone. Constraints suit a
  CA whose names are genuinely private.

Issuance is checked against the CA before anything is written. Signing a
violating certificate **succeeds** — only verification fails, with
`error 47 ... permitted subtree violation` — so without that check you would
get a clean-looking `.crt` and discover the problem in a browser. Any other
reason the CA cannot vouch for the leaf (an expired CA, for instance) is
reported the same way, verbatim, and no file is written.

### Two separate trust systems

Installing into the system store and expecting browsers to follow is the mistake
this exists to prevent. They are unrelated stores:

| | Reads | Needs root |
| --- | --- | --- |
| `curl`, `git`, `rclone`, most daemons | the OpenSSL/p11-kit **system store** | yes |
| Chrome, Chromium, Brave, Opera, Vivaldi, **Firefox** | **NSS** databases | no |

A correct system install leaves every browser still warning, with nothing to say
why. `-T all` (the default) does both.

NSS makes it worse than one database: **Firefox keeps one per profile**, and
**every Flatpak browser has its own**, because `persistent=.pki` gives the app
its own `~/.var/app/<id>/`. So a single system-wide entry reaches none of them.
`-I` discovers and populates:

- `~/.pki/nssdb` — native Chromium-family browsers
- `~/.var/app/*/data/pki/nssdb` and `~/.var/app/*/.pki/nssdb` — Flatpak apps
- `~/snap/*/current/.pki/nssdb` — Snap packages
- `~/.mozilla/firefox/*/` and the Flatpak equivalent — Firefox profiles

A directory is only used when it actually contains `cert9.db` or `cert8.db`, so
an unmatched glob is never mistaken for a path.

**Under `sudo` it drops to `$SUDO_USER` for the NSS half.** The system store
needs root and the NSS databases belong to the person at the keyboard; without
this, `sudo ignite.sh -I ca.crt` would install the anchor correctly and then
populate *root's* browser profiles, leaving the browsers exactly as untrusting
as before.

**Restart browsers fully afterwards.** NSS is read at startup, and closing the
window often leaves a background process holding the old state.

`certutil` (from `nss-tools` / `libnss3-tools`) is required for the NSS half and
is **not** installed for you. On an image-based system where layering means a
reboot, `-I` prints a ready-made `podman` command that runs `certutil` from a
container against each database instead.

It **searches nowhere**. `-I` takes a path, and if the certificate is not on the
machine then it cannot be installed — rather than some older copy in a default
directory being installed in its place. Either you have the certificate with
you, or you don't.

The trust store is chosen by which anchors directory and update command actually
exist, not by parsing `/etc/os-release`:

| Family | Anchors | Refresh |
| --- | --- | --- |
| Fedora / RHEL (and derivatives such as Bazzite) | `/etc/pki/ca-trust/source/anchors` | `update-ca-trust` |
| Debian / Ubuntu (and derivatives) | `/usr/local/share/ca-certificates` | `update-ca-certificates` |

Detecting by presence means a derivative works without being listed, and a
half-installed `ca-certificates` fails with a reason instead of a copy that
never takes effect. On Debian the installed name is forced to end in `.crt`,
because `update-ca-certificates` silently ignores anything else.

**What it refuses**, all parsed with `openssl x509` rather than matched as text:

- anything that is not a certificate. A CSR is the one that matters —
  `-----BEGIN CERTIFICATE REQUEST-----` *contains* the substring
  `BEGIN CERTIFICATE`, so a text match accepts it and a CSR gets installed as a
  trust anchor.
- a file containing a `PRIVATE KEY`, which would copy a key into a
  world-readable anchors directory.

**What it checks afterwards:** `openssl verify` against the system store with no
`-CAfile`. A self-signed CA that is now trusted verifies against itself; before
the install it does not. So the success message means the copy *and* the refresh
actually took effect, rather than that two commands exited zero.

It also warns when the certificate has no `basicConstraints CA:TRUE` — installing
a leaf trusts exactly that certificate and nothing it signed, which is rarely
what was intended.

## Options

| Flag | Meaning | Default |
| ---- | ------- | ------- |
| `-d DOMAIN` | Domain to certify: a hostname, a `*.` wildcard, or an IPv4 address (see below) — **required** | — |
| `-s SELF_SIGNED` | `1` = self-signed, `0` = CSR only | `1` |
| `-n NUMBITS` | RSA key size: `2048`, `3072`, or `4096` (validated in every mode, including `-g 1`, where it becomes the template's `default_bits`) | `2048` |
| `-t DURATION` | **Leaf** validity in days (`1`–`3650`) | `398` |
| `-c CA_DURATION` | **CA** validity in days (`1`–`7300`) | `3650` |
| `-f CONFIGURATION_FILE` | `openssl` config file (mutually exclusive with `-i`; if both, `-f` wins) | — |
| `-i SUBJECT` | Subject string, e.g. `/C=PT/O=Acme/CN=example.com` | — |
| `-a SUBJECT_CA` | CA subject string (self-signed only; ignored when an existing CA is reused) | a placeholder CA |
| `-g TEMPLATE` | `1` = write a `.cfg` template for the domain and exit | `0` |
| `-k PRIVATE_KEY` | `.key` file to pair with `-r` when building a `.pem` (without `-r` it is ignored with a warning) | — |
| `-r CRT_FILE` | `.crt` file to convert into `.cert` (and `.pem` with `-k`) | — |
| `-o OUTPUT_DIR` | Directory to write output into (default `./certificates`) |
| `-I INSTALL_FILE` | Install this certificate into the system trust store (needs root) |
| `-N INSTALL_NAME` | Filename to install it as (default: `younglings-<fingerprint8>.crt`). No `/` and no leading `.` |
| `-T INSTALL_TARGET` | Where `-I`/`-U` acts: `system`, `nss`, or `all` (default) |
| `-U` | With `-I`: **remove** that certificate from the store instead of installing it |
| `-C NAME_CONSTRAINTS` | Limit a **newly built** CA to these names, comma-separated (`.lan,.nip.io,192.168.0.0/16`). Off by default |
| `-E` | Encrypt a **newly built** CA key with AES-256. Needs `-p` or a terminal | off |
| `-p CA_PASSPHRASE_FILE` | File holding the CA key passphrase. `YOUNGLINGS_CA_PASSPHRASE_FILE` does the same | — |
| `-R` | Move an existing CA key into the `0700` `ca-private/` directory, then exit | — |
| `-h` | Show help and exit | — |

**Domains** (`-d`) may be a regular hostname (`example.com`, `sub.example.com`),
`localhost` or any other single-label host (`myhost`), a wildcard (`*.example.com`),
or a dotted-quad IPv4 address (`192.168.1.10`). Anything else is rejected.

**Subject strings** are a run of `/Key=Value` pairs in any order and must include at
least `/C=`, `/O=`, and `/CN=` (e.g. `/C=PT/ST=Lisboa/O=Acme/OU=IT/CN=example.com`).

**Subject Alternative Names.** Issued CSRs and certificates always carry a SAN, since
modern clients ignore the CN. With `-i` it is derived from `-d`: `DNS:<domain>` for
hostnames and wildcards, `IP:<address>` for IPv4. With `-f` the SAN comes from the
config's `req_ext`/`alt_names` section and is copied from the CSR into the signed
`.crt` (on OpenSSL 3 via `-copy_extensions`, on older OpenSSL/LibreSSL via a temporary
`-extfile`). The `-g 1` template pre-fills `alt_names` to match the domain: the host
plus `www.` for hostnames, the wildcard plus its apex, or `IP.1` for an address.

**CA reuse.** In self-signed mode, an existing CA key + `ca.crt` pair is reused,
so certificates issued on later runs are trusted by the same CA you already
installed. To start over with a fresh CA, delete both.

## Output files

For a domain `example.com`, `./certificates/` will contain, depending on the mode:

- **CSR mode**: `example.com.key`, `example.com.csr`
- **Self-signed**: `ca-private/ca.key` (mode `0600`, in a `0700` directory),
  `ca.crt`, `ca.srl`, `example.com.key`, `example.com.csr`, `example.com.crt`,
  `example.com.cert`, `example.com.pem`
- **Template**: `example.com.cfg`
- **Conversion**: `example.com.cert` (+ `example.com.pem` when `-k` is given)

`ca.srl` is the CA's serial-number counter, maintained by `openssl` across runs.
`.pem` bundles contain the **private key** followed by the certificate, so they are
written with `0600` permissions — keep them out of version control.

### What a signed leaf carries

A CA-signed leaf is given the extensions that say it is a leaf, where the CSR
has not already said so itself:

| Extension | Value |
| --- | --- |
| `basicConstraints` | `critical, CA:FALSE` |
| `keyUsage` | `critical, digitalSignature, keyEncipherment` |
| `extendedKeyUsage` | `serverAuth, clientAuth` |

Only where the CSR is **silent**. If your config file or template already
requests any of the three, yours is kept — the point is to stop a leaf going
out with no constraints at all, not to override what you asked for.

Without `CA:FALSE` a leaf is, formally, a certificate that could sign others.
Most clients will not honour that, but "most" is not a property worth relying
on, and it costs one line in an extfile to be unambiguous.

This applies to certificates signed **from now on**. Nothing re-issues or
invalidates a certificate you already have — the extensions are written at
signing time, so an existing leaf keeps whatever it was signed with.

## Testing

```sh
tests/run-all.sh        # every tests/test-*.sh; non-zero exit if any fails
```

**45 + 64 checks**, in two files. Everything runs as an ordinary user against
temporary directories.

`tests/test-install.sh` covers what `-I` refuses, that `-o` is honoured, that
the leaf is CA-signed and carries a SAN and the extensions above, that NSS
discovery never returns an unexpanded glob, and that `nss_home` follows
`$SUDO_USER`.

`tests/test-ca-key.sh` covers the CA key: where it lands and with which modes,
that `-t` and `-c` move independently, that `-E` produces a key that is
actually encrypted and can still sign a second leaf, every refusal of a bad
passphrase source, and that a key at the old path is reused rather than
replaced until `-R` moves it. Run against the previous commit it fails 36 of
its checks.

Its `run()` captures **both** streams, because the engine sends `msg()` to
stdout and `wrn()`/`oerr()` to stderr: a suite watching one of them asserts on
half the output. And every invocation has stdin closed, which is the only thing
that makes the "`-E` with no passphrase source is refused" check mean
anything — the bug it guards printed that refusal from inside a command
substitution, where `execution_error` exits only the subshell. The caller then
ran `openssl genrsa -aes256` with no passphrase argument at all, `openssl`
prompted, took the EOF as an empty passphrase, and wrote a usable
**unencrypted** key after saying it had refused.

One part of it is about the suite rather than the tool, and exists because the
suite used to be the bug. The `-T` acceptance checks ran `-I ca.crt -T nss`
just to see whether the flag parsed — and that performs the **whole install**,
so every run added a throwaway CA to every NSS database on the machine and then
deleted its key. On the author's laptop that is five databases: `~/.pki/nssdb`
plus four Flatpak browsers.

Two defences now. The flag checks call the validators directly instead of
running an install. And `certutil`, `update-ca-trust`,
`update-ca-certificates` and `trust` are **shadowed on `PATH` by hard
failures** (exit 97), so a future edit that reintroduces a real install fails
the suite instead of quietly modifying the machine it runs on.

The NSS install is also read back with `certutil -L -n <nickname>` rather than
trusted to a zero exit status, and the read-back looks for the nickname in the
listing body. An earlier version matched against `certutil`'s own column
header, which is present whether or not anything was installed.

The *successful* installs need root and a real store, so they are checked in
containers of both families — `verification failed` before, `OK` after:

```sh
podman run --rm -v "$PWD:/e:ro" registry.fedoraproject.org/fedora:41 \
  bash -c 'dnf -q -y install openssl ca-certificates nss-tools && bash /e/ignite.sh -I /e/ca.crt'
```

### CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `shellcheck -x` on
`ignite.sh` and the whole suite, on every push to `main`, every pull request,
and on demand. `-x` matters here: this tool is a sourced-file program, so shellcheck has to
follow the `source` chain to see one program instead of nine files of
apparently undefined variables. `shellcheck *.sh` reports **102** findings that
are all that same non-problem; `shellcheck -x ignite.sh` reports **0**.

The container checks above are **not** in CI; they need root and a real trust
store, so they stay a manual step.

## Project layout

| File | Purpose |
| ---- | ------- |
| `ignite.sh` | Main entry point — parses flags, validates, dispatches. |
| `functions.sh` | Helpers and validators (usage, colour output, parameter validation). |
| `protocols.sh` | The generation flows (self-signed, CSR, template, conversion). |
| `parameters.sh` | Default parameter values. |
| `constants.sh` | Configuration constants. |
| `variables.sh` | Derived variables (output path). |
| `regex.sh` | Validation regular expressions. |
| `errors.sh` | Error message strings. |
| `colors.sh` | Terminal colour codes. |

## Contributing

Fork → branch → change → PR. Please keep it `openssl`-only and flag-driven (no
interactive prompts), so it stays scriptable.

## License

[MIT](LICENSE) © 2026 malahmen.
