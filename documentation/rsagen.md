# RSA Key Generation

Foil can create ECDSA private and public keys. By default, both the public and private keys are created and saved whenever ECDSA generation is called. 

## Usage

```bash

$: foil rsagen [operation] [path to input file] [path to output file] [flags]

```

### Available Flags

`--gen` - Generate a new RSA public and private key in PEM format
`--pub` - Given a private key in PEM format, extract and save the public key in PEM format
`--size` - Create an RSA key of size [int]; [int] must be 2048, 3072, 4096

### Examples

Generate a private key,

```bash

$: foil rsagen --gen --size 2048 --out testPriv.pem

$: ls

  testPriv.pem

```

Print private key to StdOut

```bash

$: foil rsagen --gen --size 2048 --textout

-----BEGIN EXAMPLE RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAlkzBFk8h2DNyhVBq7/KHqsbTo3DHl4JPCq4snULTmeI7NFiC
A0aE6X3q414wdbu3lWpRP0XR+fDHqP99Xq7WrLk+mylT9NYjqda+YGQQ5ul7ghdD
nzLFpHcW2hu7lWQBn1qw85NqRyVG6Q6qZhVSOYp8U1RkWTuvMjkxbgBIIX8kNUQ7
Fzo/BHBfW7/UUoiGv5QON6YaRD8e5U9R72i3g4mVu1kr7Af4sW+vV+BUiVhIRyY3
QfmiUpCybhelLuXgha20IsxAI2W8AnJESZ4G1OVUIqAUAUMfSIg/Y1qn4gJGSHU8
qW/hjQLk1SDKKNmbBKXHVVgYfPemhYHITS2+XQIDAQABAoIBAECSYTIwdR3pnH3h
+s9zpw2btjk1rspM1aCFC+3UVAx8wWrPy6uUlG2sB0n/oVozd7/dmWJRoNB8vYrB
mR8ghmJWg6stqkA578B73faThx9tl/5f+FFhAsCR2WODHqgj+v53fCZpYvOF9F0U
S+jnqBfIg3lZfHNJzQ8Ku03DGToqONsSuth8BC9pPR1VWdPmakzHl6eVOkBHiI5v
Y1jFp3LoyfvWMXkW8+YqjTtNHS3oo4ytKUMJZ9hr1knFSacTFsNzzIjX0Rwc7Bvk
DpzTNX3/rnNxBicY6B9dXcdzxz0fSGbKXAQIgR+Umk19oojOUU0hfBKX8anNjOcY
zXI1bxECgYEAwsav5NDzYySTLvUgtiVyRStq7YNtr2m0+J6ArIJdhLRpCTGr2s80
WJI+8oS2WZWPSJzW444i1YzvAX/REy0tBXsRRSMVhUTrJ58P3Q/Cj1fvMqQtmzb4
LZoXmhomcHsE0eL4CkAyJSfBKRLRzHxU0dkJs2SAu31Yv8Ff4faS5Z8CgYEAxYsh
+d5YWJ/qKv6xhzKmLxMIwWzbVTylfcMUdUWvAGWVLPR0R1X+mrqlDO2xH1R5J+ng
Rn+yxMEWoOnznkvMcRN2NcjwbfMeKhx2teuJ6CXPpgeiksGlQUD+JXEyC9ME0t0e
B9Z9AdKjcHThRBkbsnsyFphRx0CVIUcUurRpAoMCgYEAk5uDPULk0COtrw5xpdgn
CyhmNm09uIvBbBCirxl0ydb3KtKLzJzurJjYP243yxg+p+bEK1tSJshRcK9uwLuh
vN+RLPXznzWliDdRDFSfO4aGbbhiH5i+58A5Vr2ul9uCwZTiKNKRrfq8teXfPLqU
hRuX8G2f6XaKxXdEtLfqhz0CgYEAmNPRD0yTMM1XDrhIg/4NT3H8Xhhnf4QRzD/2
PdwRTc9JH6RnqSDAfthTBLOHSmPB770ig6gbl9iCNy+ICDlAC2MxGt9AEu/5sD6h
IJD++hj2ks5pWfxyaw9rD3CJdVhl7PSgXRP1VkmtpDzoYhTCtsxUreJdsjcmqL4j
LWaRrx0CgYBb2EFZjZbOYwgCU++xgGuC5CGGllNIO/D3WoORfLawAQIarPOPK5tM
sL/U0tgTD5sxAKhX+ZoM4fPibuWD3bYeFRL37U6Z4yxbVts7iCIwtv/KuGAL71No
D9x7IOSNP18dS037UF9Elok4ig4ks6sNSONSeIL5Jr78pvOViqM9Fg==
-----END EXAMPLE RSA PRIVATE KEY-----

```

Extract a public key,

```bash

$: foil rsagen --pub --out testPub.pem --in testPriv.pem

$: ls

  testPriv.pem  testPub.pem

```

## Additional Details

RSA prime search and testing is not performed with constant time algorithms.

## Contributors

Brian Vohaska