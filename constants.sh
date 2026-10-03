CERTIFICATES_DIR="certificates"
PEM_AND_CERT_FILES="pem_and_cert_files"
CONFIGURATION_FILE_TEMPLATE="configuration_file_template"
# Trust stores, by the files each family actually uses. Detected by presence
# rather than by parsing /etc/os-release: that way a derivative (bazzite, Mint,
# Pop) works without being listed, and a distro that moves its anchors is caught
# instead of silently matching on ID_LIKE.
TRUST_ANCHORS_RHEL="/etc/pki/ca-trust/source/anchors"
TRUST_UPDATE_RHEL="update-ca-trust"
TRUST_ANCHORS_DEBIAN="/usr/local/share/ca-certificates"
TRUST_UPDATE_DEBIAN="update-ca-certificates"
INSTALL_CERTIFICATE="install_certificate"
