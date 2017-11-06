# ECDSA Generation

Foil can create ECDSA private and public keys. By default, both the public and private keys are created and saved whenever ECDSA generation is called. 

## Usage

```bash

$: foil ecgen [path to output file] [operation] [fags]

```

### Available Flags

`--gen` - Generate a new ECDSA (P-256) public and private key in PEM format
`--pub` - Given a private key in PEM format, extract and save the public key in PEM format

### Examples

Generate a private key,

```bash

$: foil --gen --out testOut.pem

$: ls

  testout.pem

```

Print private key to StdOut

```bash

$: foil --gen --out testPriv.pem --textout

-----BEGIN EXAMPLE PRIVATE KEY-----
MHcCAQEEIMoiNS9ehBTGmuWyDkkOPNGKg8XjxqD6opY3PrexThPnoAoGCCqGSM49
AwEHoUQDQgAESNmuVUrMuAjTuOcmrADe7ZtgnDn7BUHHmplpYgE7xzCnkFsD7/ia
Czz/HNG/Fm+gyEwppz6FEa9742InsR1jTQ==
-----END EXAMPLE KEY-----


$: ls

  testPriv.pem

```

Extract a public key,

```bash

$: foil --pub --out testPub.pem --in testPriv.pem

$: ls

  testPriv.pem  testPub.pem

```

## Additional Details

ECDSA keys are generated on P-256 and saved as PEM files. New curves will eventually be supported.

## Contributors

Brian Vohaska