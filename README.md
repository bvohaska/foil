# Foil: A simple CLI tncryption tool & much more

Foil provides a simple UI to provide a crypto-playground to the user. In tis way, foil was desinged to allow users to experiment with cryptography while also providing useful  AES-256-GCM encryption and decryption with a 96-bit IV/nonce.

Foil uses the Cobra package to display CLI usage and help. For more information on Cobra, see: <https://github.com/spf13/cobra>.

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

Ensure that you have access to the "golang.org/x/crypto/pbkdf2" package. The 'go get' will fetch this for you if your $GOPATH is correctly set-up.

Install Cobra:  <https://github.com/spf13/cobra>

Typically this can be done using hte following command:

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

## Using the encryption tool

Locate the binary that was just built. Enter the following on the first try,

```bash

$: ./foil --help

```

For encryption, simply follow the usuage instructions to supply an input and specify an output and the tool will encrypt; notice that you do not need to provide a key if you would like for a 256-bit key to be randomly generated for you. Example,

```bash

$: ./foil enc --textin "Attack at dawn!" --textout --password "LegitPa$$word1999" --adata "I love encryption"

```

Note: If a password (string) or key (in hex) is not provided, the encryption function will randomly genereate one using os random.

For decryption, you must supply a key (hex) or password in addition to an input file and output destination. Example,

```bash

$: ./foil dec --textin [hex of ciphertext] --textout --password "LegitPa$$word1999" --adata "I love encryption"

```

## Contributors

Brian Vohaska