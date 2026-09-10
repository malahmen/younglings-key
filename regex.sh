# One or more /Key=Value pairs, any order. Required fields (/C= /O= /CN=) are
# checked separately in validate_subject so order never matters.
re_subject='^(/[A-Za-z]+=[^/]*)+$'

# Hostname: labels of [a-z0-9-], optionally with a leading "*." wildcard; a
# single label (localhost, myhost) is fine. IPv4 is matched separately.
re_hostname='^(\*\.)?[a-zA-Z0-9](-*[a-zA-Z0-9])*(\.[a-zA-Z0-9](-*[a-zA-Z0-9])*)*$'
re_ipv4='^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
