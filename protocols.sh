# Self Signed Certificate - initialization
self_signed_protocol(){
  if [ -z "$CONFIGURATIONS" ]; then
    self_signed_protocol_configured
  else
    self_signed_protocol_subject
  fi
}
# Self Signed Protocol with configuration file
self_signed_protocol_configured(){
  # validate encryption bits value
  validate_numbits $NUMBITS
  # validate certificate duration
  validate_duration $DURATION
  # validate the certificate authority information
  validate_subject $SUBJECT_CA
  
  $CERTIFICATES_PATH = "$SCRIPT_DIR/$CERTIFICATES_DIR"
  execute mkdir -p $CERTIFICATES_PATH

  # Generate the CA key
  execute openssl genrsa -out "$CERTIFICATES_PATH/ca.key" $NUMBITS
  # Generate the CA certificate
  execute openssl req -x509 -new -nodes -sha512 -days $TIME -subj $SUBJECT_CA -key "$CERTIFICATES_PATH/ca.key" -out "$CERTIFICATES_PATH/ca.crt"
  # Generate your private key
  execute openssl genrsa -out "$CERTIFICATES_PATH/$DOMAIN.key" $NUMBITS
  # Generate your certificate signing request
  execute openssl req -sha512 -new -key "$CERTIFICATES_PATH/$DOMAIN.key" -out "$CERTIFICATES_PATH/$DOMAIN.csr" -config "$CONFIGURATION_FILE"
  # Check the CSR file
  execute openssl req -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.csr"
  # Sign your certificate using the CA
  execute openssl x509 -req -sha512 -days $TIME -CA "$CERTIFICATES_PATH/ca.crt" -CAkey "$CERTIFICATES_PATH/ca.key" -CAcreateserial -in "$CERTIFICATES_PATH/$DOMAIN.csr" -out "$CERTIFICATES_PATH/$DOMAIN.crt"
  # Check it
  execute openssl x509 -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.crt"
  # Generate the .cert file that some systems might request
  execute openssl x509 -inform PEM -in "$CERTIFICATES_PATH/$DOMAIN.crt" -out "$CERTIFICATES_PATH/$DOMAIN.cert"
  # Generate the .pem file for your certificate
  execute cat "$CERTIFICATES_PATH/$DOMAIN.key" "$CERTIFICATES_PATH/$DOMAIN.crt" > "$CERTIFICATES_PATH/$DOMAIN.pem"
}
# Self Signed Protocol with configuration string - subject
self_signed_protocol_subject(){
  # validate encryption bits value
  validate_numbits $NUMBITS
  # validate certificate duration
  validate_duration $TIME
  # validate the certificate authority information
  validate_subject $SUBJECT_CA
  # validate the certificate information
  validate_subject $SUBJECT
  
  $CERTIFICATES_PATH = "$SCRIPT_DIR/$CERTIFICATES_DIR"
  execute mkdir -p $CERTIFICATES_PATH

  # Generate the CA key
  execute openssl genrsa -out "$CERTIFICATES_PATH/ca.key" $NUMBITS
  # Generate the CA certificate
  execute openssl req -x509 -new -nodes -sha512 -days $TIME -subj $SUBJECT_CA -key "$CERTIFICATES_PATH/ca.key" -out "$CERTIFICATES_PATH/ca.crt"
  # Generate your private key
  execute openssl genrsa -out "$CERTIFICATES_PATH/$DOMAIN.key" $NUMBITS
  # Generate your certificate signing request
  execute openssl req -sha512 -new -subj $SUBJECT -key "$CERTIFICATES_PATH/$DOMAIN.key" -out "$CERTIFICATES_PATH/$DOMAIN.csr"
  # Check the CSR file
  execute openssl req -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.csr"
  # Sign your certificate using the CA
  execute openssl x509 -req -sha512 -days $TIME -CA "$CERTIFICATES_PATH/ca.crt" -CAkey "$CERTIFICATES_PATH/ca.key" -CAcreateserial -in "$CERTIFICATES_PATH/$DOMAIN.csr" -out "$CERTIFICATES_PATH/$DOMAIN.crt"
  # Check it
  execute openssl x509 -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.crt"
  # Generate the .cert file that some systems might request
  execute openssl x509 -inform PEM -in "$CERTIFICATES_PATH/$DOMAIN.crt" -out "$CERTIFICATES_PATH/$DOMAIN.cert"
  # Generate the .pem file for your certificate
  execute cat "$CERTIFICATES_PATH/$DOMAIN.key" "$CERTIFICATES_PATH/$DOMAIN.crt" > "$CERTIFICATES_PATH/$DOMAIN.pem"
}
# Certificate Request - initialization
certificate_request_protocol(){
  if [ -z "$CONFIGURATIONS" ]; then
    certificate_request_protocol_configured
  else
    certificate_request_protocol_subject
  fi
}
# Certificate Request with configuration string - subject
certificate_request_protocol_subject(){
  # validate encryption bits value
  validate_numbits $NUMBITS
  # validate the certificate information
  validate_subject $SUBJECT
  
  $CERTIFICATES_PATH = "$SCRIPT_DIR/$CERTIFICATES_DIR"
  execute mkdir -p $CERTIFICATES_PATH
  
  # Generate your private key
  execute openssl genrsa -out "$CERTIFICATES_PATH/$DOMAIN.key" $NUMBITS
  # Generate your certificate signing request
  execute openssl req -sha512 -new -subj $SUBJECT -key "$CERTIFICATES_PATH/$DOMAIN.key" -out "$CERTIFICATES_PATH/$DOMAIN.csr"
  # Check the CSR file
  execute openssl req -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.csr"
}
# Certificate Request with configuration file
certificate_request_protocol_configured(){
  # validate encryption bits value
  validate_numbits $NUMBITS
  
  $CERTIFICATES_PATH = "$SCRIPT_DIR/$CERTIFICATES_DIR"
  execute mkdir -p $CERTIFICATES_PATH

  # Generate your private key
  execute openssl genrsa -out "$CERTIFICATES_PATH/$DOMAIN.key" $NUMBITS
  # Generate your certificate signing request
  execute openssl req -sha512 -new -key "$CERTIFICATES_PATH/$DOMAIN.key" -out "$CERTIFICATES_PATH/$DOMAIN.csr" -config "$CONFIGURATION_FILE"
  # Check the CSR file
  execute openssl req -text -noout -in "$CERTIFICATES_PATH/$DOMAIN.csr"
}
# Generate a configuration file template (needs g TEMPLATE parameter, requires DOMAIN parameter)
# Generate a .cert file and .pem file from the .crt file (needs k PRIVATE_KEY, r CRT_FILE parameters)