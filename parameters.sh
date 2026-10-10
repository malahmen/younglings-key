# Default parameter values. Overridable via flags (see functions.sh).
DOMAIN=""
SELF_SIGNED="1"                 # 1 = self-signed (default), 0 = CSR only
NUMBITS="2048"                  # 2048 | 3072 | 4096
# LEAF validity, in days. 398 and not 3650: Apple platforms refuse any
# certificate issued after 2019-07-01 with a lifetime over 825 days, whatever
# root signed it, so a ten-year leaf was already unusable on macOS and iOS
# while looking fine in Chrome and Firefox. 398 is the current public maximum
# (the CA/Browser Forum limit browsers enforce for public CAs), which keeps the
# same certificate usable everywhere and makes the renewal a habit rather than
# an event. -t still accepts up to 3650 for a host nothing Apple will ever
# talk to.
DURATION="398"                  # leaf validity in days (self-signed)
# ROOT validity, separately. A root is deliberately long-lived: shortening it
# does not reduce the damage a leaked key does, it only means re-distributing
# the anchor to every machine and browser profile that trusts it. What limits
# this CA is pathlen:0, the opt-in nameConstraints (-C) and where its key is
# kept (-E, and the 0700 directory) — not its expiry.
CA_DURATION="3650"              # CA validity in days (-c)
ENCRYPT_CA="0"                  # -E: encrypt a NEW CA key (AES-256)
CA_PASSPHRASE_FILE=""           # -p: file holding the CA key passphrase
RELOCATE_CA="0"                 # -R: move an existing CA key into the 0700 dir
CONFIGURATION_FILE=""           # openssl config file (-f)
SUBJECT=""                      # subject string (-i)
SUBJECT_CA="/C=PT/ST=Lisboa/L=Lisboa/O=Younglings/OU=Certificates/CN=Younglings Root CA"
TEMPLATE="0"                    # 1 = emit a .cfg template and exit
CRT_FILE=""                     # existing .crt to convert (-r)
PRIVATE_KEY=""                  # .key to pair with -r for a .pem (-k)
OUTPUT_DIR=""                   # output directory (-o); empty = ./certificates
INSTALL_FILE=""                 # certificate to install into the trust store (-I)
INSTALL_NAME=""                 # filename to install it as (-N); empty = basename
UNINSTALL="0"                   # -U: remove instead of install
NAME_CONSTRAINTS=""             # -C: limit a NEW CA to these names (empty = unconstrained)
INSTALL_TARGET="all"            # where -I installs: system | nss | all (-T)
