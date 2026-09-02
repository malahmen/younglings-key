# younglings-key

**`ignite.sh` — certificate generation, simplified.**

A small, gum-free, **flag-driven** CLI around `openssl`. It generates certificate
signing requests, self-signed certificates (with their own CA), ready-to-edit
`openssl` config templates, and `.cert`/`.pem` files from an existing `.crt` — with
no interactive prompts, so it drops straight into scripts and pipelines.

## Capabilities

- **Self-signed certificates** — creates a CA and signs the certificate with it (great for local dev/testing).
- **Certificate requests (CSR)** — generates a key + CSR to send to a certificate authority.
- **Config templates** — writes an `openssl` `.cfg` template for a domain that you can edit and reuse.
- **Format conversion** — produces `.cert` (and `.pem`, given the key) from an existing `.crt`.

Output is written under **`./certificates/`** in the current directory.

## Requirements

- **`openssl`** — the only hard dependency (checked at start).
- **`bash`** — the script uses `#!/usr/bin/env bash` with strict mode.

No elevated privileges are needed; it writes only under the working directory.

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

## Options

| Flag | Meaning | Default |
| ---- | ------- | ------- |
| `-d DOMAIN` | Domain to certify (e.g. `example.com`) — **required** | — |
| `-s SELF_SIGNED` | `1` = self-signed, `0` = CSR only | `1` |
| `-n NUMBITS` | RSA key size: `2048`, `3072`, or `4096` | `2048` |
| `-t DURATION` | Validity in days for self-signed certs (`1`–`3650`) | `3650` |
| `-f CONFIGURATION_FILE` | `openssl` config file (mutually exclusive with `-i`; if both, `-f` wins) | — |
| `-i SUBJECT` | Subject string, e.g. `/C=PT/O=Acme/CN=example.com` | — |
| `-a SUBJECT_CA` | CA subject string (self-signed only) | a placeholder CA |
| `-g TEMPLATE` | `1` = write a `.cfg` template for the domain and exit | `0` |
| `-k PRIVATE_KEY` | `.key` file to pair with `-r` when building a `.pem` | — |
| `-r CRT_FILE` | `.crt` file to convert into `.cert` (and `.pem` with `-k`) | — |
| `-h` | Show help and exit | — |

**Subject strings** are a run of `/Key=Value` pairs in any order and must include at
least `/C=`, `/O=`, and `/CN=` (e.g. `/C=PT/ST=Lisboa/O=Acme/OU=IT/CN=example.com`).

## Output files

For a domain `example.com`, `./certificates/` will contain, depending on the mode:

- **CSR mode**: `example.com.key`, `example.com.csr`
- **Self-signed**: `ca.key`, `ca.crt`, `example.com.key`, `example.com.csr`,
  `example.com.crt`, `example.com.cert`, `example.com.pem`
- **Template**: `example.com.cfg`
- **Conversion**: `example.com.cert` (+ `example.com.pem` when `-k` is given)

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

Released under the [Unlicense](LICENSE).
