# Simple CLI Encryption Tool

This is a simple tool desinged to perform AES-256-GCM encryption and decryption and uses a 96-bit IV/nonce. The tool has many command-line options that can veiwed by running the binary with the flag '--help'. These flags are also prominately displayed in encryptor.go.


## Getting Started

In order to get started you will need to install golang and set up your go workspace.


### Prerequisites

Install golang (https://golang.org/doc/install).

Set up your go environment ($GOROOT and $GOPATH); See the above link for more details. On linux go is typically installed in /user/local with a $GOPATH set to ~/go.

Git clone this repository. Make sure the directory structure is appropriate for your environment. Example:
```
 go/
    src/
        encryptor/
            encryptor.go
            helpers/
                helperCore.go
    pkg/

    bin/

```

Ensure that you have access to the "golang.org/x/crypto/pbkdf2" package. The go tool will fetch this for you if your $GOPATH is correctly set-up.

### Building for the first time

To build the encryptor there are two options:
```
$: go build
```
Which will build a copy of encryptorCore and save the binary to the $PWD
```
$: go install
```
Which will build a copy of encryptorCore and save the binary in $GOPATH/bin

### Using the encryption tool

Locate the binary that was just built. Enter the following on the first try.
```
$: ./encryptorcore --help
```
For encryption, simply follow the usuage instructions to supply an input and specify an output and the tool will encrypt; notice that you do not need to provide a key if you would like for a 256-bit key to be randomly generated for you. 

For decryption, you must supply a key (hex) or password in addition to an input file and output destination.

## Contributors

Brian Vohaska