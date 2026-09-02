# Default parameter values. Overridable via flags (see functions.sh).
DOMAIN=""
SELF_SIGNED="1"                 # 1 = self-signed (default), 0 = CSR only
NUMBITS="2048"                  # 2048 | 3072 | 4096
DURATION="3650"                 # certificate validity in days (self-signed)
CONFIGURATION_FILE=""           # openssl config file (-f)
SUBJECT=""                      # subject string (-i)
SUBJECT_CA="/C=PT/ST=Lisboa/L=Lisboa/O=Younglings/OU=Certificates/CN=Younglings Root CA"
TEMPLATE="0"                    # 1 = emit a .cfg template and exit
CRT_FILE=""                     # existing .crt to convert (-r)
PRIVATE_KEY=""                  # .key to pair with -r for a .pem (-k)
