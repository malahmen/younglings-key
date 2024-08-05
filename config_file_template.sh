[ req ]
default_bits        = 2048
default_keyfile     = vaiken.spacedock.key # provide vaiken.spacedock value as the domain parameter 
default_md          = sha256
distinguished_name  = req_distinguished_name
req_extensions      = req_ext
x509_extensions     = v3_ca # Extensions to add for self-signed certs (if needed)

[ req_distinguished_name ]
countryName          =
countryName_default  = US
stateOrProvinceName  =
stateOrProvinceName_default  = Drommund Kaas
localityName         =
localityName_default = Kaas City
organizationName     = 
organizationName_default = Sith Empire
commonName           = 
commonName_default   = vaiken.spacedock
commonName_max       = 64

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1   = vaiken.spacedock
DNS.2   = www.vaiken.spacedock
DNS.3   = cantina.vaiken.spacedock
DNS.4   = supplies.vaiken.spacedock
DNS.5   = crew-skills.vaiken.spacedock
DNS.6   = combat-training.vaiken.spacedock
DNS.7   = galatic-trade-market.vaiken.spacedock
# Add more DNS.8, DNS.9, etc., as needed
IP.1    = 192.168.1.141
# Add more IP.2, IP.3, etc., as needed
