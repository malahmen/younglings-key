# Certificate Generation Script (CGS)

## Description
The Certificate Generation Script (CGS) is a versatile tool designed to streamline the management and generation of web certificates. 

It simplifies the process of creating certification requests, self-signed certificates, and more, making it ideal for developers and system administrators.

## Installation
Follow these steps to install the CGS on your system:

```sh
# Clone the repository
git clone git@github.com:malahmen/cgs.git

# Change directory
cd cgs

# There are no dependencies to install, proceed to usage
```

## Usage
To use CGS, navigate to the cloned directory and execute the script with the desired options:

```sh
# Generate a configuration file for your domain
./cgs.sh -d my-domain.com -g 1

# Customize the generated my-domain.cfg file as needed

# Generate a CSR using the customized configuration file
./cgs.sh -d my-domain.com -f my-domain.cfg
```

## Features
CGS offers a variety of features to accommodate different needs:
- **Certificate Requests:** Generate CSR files to submit to certificate authorities.
- **Self-Signed Certificates:** Create certificates for local development and testing.
- **Certificate and Key Management:** Generate `.cert` and `.pem` files from existing certificate and key files.
- **Configurable Templates:** Use customizable templates instead of manual subject strings for requests.

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
