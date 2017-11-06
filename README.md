# Foil: A simple CLI *cryption tool & much more

Foil is a CLI tool that provides easy access to new and exciting cryptograhic primitives. In tis way, foil was desinged to allow users to experiment with cryptography while also providing more common features such as AES-256-GCM for encryption and decryption.

Foil uses the Cobra package to display CLI usage and help. For more information on Cobra, see: <https://github.com/spf13/cobra>.

## Current Features

* AES-256-GCM w/ 96-bit nonce
* ECDSA generation
* RSA generation
* EC-OPRF based on <https://eprint.iacr.org/2017/111>
* VRFs based on <https://eprint.iacr.org/2017/099.pdf>

## Proposed Features

- [ ] Curve25519 support
- [ ] VRF standard input/output files
- [ ] NSEC5 generation/ validation support

## Getting Started

In order to get started you will need to install golang, and set up your go workspace, and download the requisite libraries.

### Prerequisites

Install golang <https://golang.org/doc/install>.

Set up your go environment ($GOROOT and $GOPATH); See the above link for more details. On linux go is typically installed in /user/local with a $GOPATH set to ~/go.

Git clone this repository. Make sure the directory structure is appropriate for your environment. Example:

```go

go/
    src/
        foil/
            main.go
            helpers/
                helpers.go
            commands/
                ...
    pkg/

    bin/

```

Ensure that you have access to the "golang.org/x/crypto/pbkdf2" package.

If your go environnment is not set up to automatically fetch new golang.org packages, you can install pbkdf2 the 'go get' command. This will fetch packages for you if your $GOPATH points to your current go workspace:

```bash

$: go get golang.org/x/crypto/pbkdf2

```

Install Cobra:  <https://github.com/spf13/cobra>

Typically, this can be done using the following command:

```bash

$: go get -u github.com/spf13/cobra/cobra

```

### Building for the first time

To build the encryptor there are two options:

```bash

$: go install

```

Which will build a copy of encryptorCore and save the binary in $GOPATH/bin

```bash

$: go build

```

Which will build a copy of encryptorCore and save the binary to the $PWD

## Using foil

Locate the binary that was just built. Enter the following on the first try,

```bash

$: ./foil --help

```

Alternatively, consider adding your local go/bin to your path,

```bash

$: echo "[path to local go workspace]\go\bin" >> .profile

```

This will allow you to access foil by simply typing 'foil' in your terminal if you built foil using 'go install'

### Using foil for Encryption & Decryption

For encryption, simply follow the usuage instructions to supply an input and specify an output and the tool will encrypt; notice that you do not need to provide a key if you would like for a 256-bit key to be randomly generated for you. 

Note: foil saves the AES IV (nonce) in the first 12 bytes of output

Example,

```bash

$: ./foil aes enc --textin "Attack at dawn!" --textout --password "LegitPa$$word1999" --adata "I love encryption"

```

Note: If a password (string) or key (in hex) is not provided, the encryption function will randomly genereate one using os random.

For decryption, you must supply a key (hex) or password in addition to an input file and output destination. Example,

```bash

$: ./foil aes dec --textin [hex of ciphertext] --textout --password "LegitPa$$word1999" --adata "I love encryption"

```

### Using other foil features

Other features are much more involed. For documentation, see the Documentation folder.

## Contributors

Brian Vohaska