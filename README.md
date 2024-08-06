# Certificate Generation Script (CGS)

## Description
The Certificate Generation Script (CGS) is a versatile tool designed to streamline the management and generation of web certificates. 

It simplifies the process of creating certification requests, self-signed certificates, and more, making it ideal for developers and system administrators.

## Capabilities

- **Certificate Requests:** Generate CSR files to submit to certificate authorities.
- **Self-Signed Certificates:** Create certificates for local development and testing.
- **Certificate and Key Management:** Generate `.cert` and `.pem` files from existing certificate and key files.
- **Configurable Templates:** Use customizable templates instead of manual subject strings for requests.

## Usage

### Installation
Follow these steps to install the CGS on your system:

```sh
# Clone the repository
git clone git@github.com:malahmen/cgs.git

# Navigate to the cloned directory
cd cgs

# Give it permitions to execute
chmod +x cgs.sh

# There are no dependencies to install, proceed to usage
```
### Execution

Execute the script with the desired options:

```sh
# Generate a configuration file for your domain
./cgs.sh -d my-domain.com -g 1

# Customize the generated my-domain.cfg file as needed

# Generate a CSR using the customized configuration file
./cgs.sh -d my-domain.com -f my-domain.cfg
```

## Options

- `-d` <**DOMAIN**>: Set the domain to get certified
- `-s` <**SELF_SIGNED**>: Set the certificate to be self-signed (0/1)
- `-n` <**NUMBITS**>: Set the value of bits to be used in the generation process
- `-t` <**DURATION**>: Set the duration of the certificate in days
- `-f` <**CONFIGURATION_FILE**>: Set the name of the external configuration file (ignores the subject option)
- `-i` <**SUBJECT**>: Set the subject string for the certificate (ignores the configuration file option)
- `-a` <**SUBJECT_CA**>: Set the subject string for the certificate authority if self-signed
- `-g` <**TEMPLATE**>: Generate a configuration file template (0/1, needs a domain parameter)
- `-k` <**PRIVATE_KEY**>: Set the name of the .KEY file to use for generating a .PEM file
- `-r` <**CRT_FILE**>: Set the name of the .CRT file to use for generating a .PEM file

## Files
- `cgs.sh`: The main generation script.
- `colors.sh`: Terminal colors to enhance the user interface.
- `constants.sh`: Configuration constants used throughout the script.
- `errors.sh`: Error messages and handling for better troubleshooting.
- `functions.sh`: Houses various functions used in the script for different tasks.
- `parameters.sh`: Default values for parameters used in the installation process.
- `protocols.sh`: Holds the execution flow for each feature.
- `regex.sh`: Regular expressions used are declared here.
- `variables.sh`: Variables required for the script, dependent on constants and parameters.

## Contributing
Contributions are welcome! Here's how you can contribute:

```sh
# Fork the repository
# Create a new branch for your feature or fix
# Make your changes
# Submit a pull request for review
```

## License
This project is released under the [unlicense](LICENSE.md). See the LICENSE file for more details.

## Acknowledgments
Special thanks to the contributors and supporters of the CGS project, whose efforts have made this tool more effective and accessible.(Me and my ego so far.)
