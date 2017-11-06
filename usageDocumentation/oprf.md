# RSA Key Generation

Foil can generate interactive OPRF responses based on <https://eprint.iacr.org/2017/111>.

## Usage

```bash

$: foil oprf [operation] [path to input] [flags]

```

### Available Flags

`--mask` - Step (1) in the OPRF protocol. Hash a message into the curve and mask with a secret value `s`.

`--salt` - Step (2) in the OPRF protocol. Given a private key in PEM format, extract and save the public key in PEM format

`--unmask` - Step (3) in the OPRF protocol. Create an RSA key of size [int]; [int] must be 2048, 3072, 4096

### Support Flags

`--rinv` - [hex] The multiplicative modular inverse (mod Curve Order) of the masking secret `r`

`--s` - (optional) [hex] The secret salting value

`--x` - [hex] The x-coordinate of the elliptiuc curve point

`--y` - [hex] The y-coordinate of the elliptic curve point

### Examples

Start the OPRF protocol,

```bash

$: foil oprf --mask --textin legitString

  Masked x-coordinate (hex): 8bee00954fb3a4489f1c2fde03665cb1a4a31241c790cacc74bc7cf931937fef
  Masked y-coordinate (hex): 6d7425a7647c77e9097bc939b9e61aefbec486d18d32211258d107a3a6e11f21
  SECRET - r inverse  (hex): cf09cd6672174e04b25ae91fae42bd0fd8bee49157f2a7448e35cc07f0ce0608

```

Note that the output can be interpereted as (x,y)--a point on the curve--and r-inv--an integer mod Curve Order

Salt a masked point,

```bash

$: foil oprf --salt \
  --x 8bee00954fb3a4489f1c2fde03665cb1a4a31241c790cacc74bc7cf931937fef \
  --y 6d7425a7647c77e9097bc939b9e61aefbec486d18d32211258d107a3a6e11f21

  Warning: No salt value given; generating a random salt
  SECRET - s (new)  : 68360655384827526033123568550619125901830448722150474620393391659893109872407
  SECRET - new s generated (hex): 9722c2822f2b4dffd780b273d7affdf444a02c543fcf8bc0ed2c07d0af98d717
  SECRET - s given (hex)        : <nil>
  Salted x-coordinate (hex): 27fe1c4d91471ad5045b66e22b52f0345d2aaccf22995acf06e84be0ca82ac70
  Salted y-coordinate (hex): 25d76b0fcc7d243c53ca6bb0316590da400587f517e348671349c44883ec079d

```

Note that a salt `s` can be provided. If not supplied, a new `s` will be generated.

Unmask a salted point,

```bash

$: foil oprf --unmask \
  --rinv cf09cd6672174e04b25ae91fae42bd0fd8bee49157f2a7448e35cc07f0ce0608 \
  --x 27fe1c4d91471ad5045b66e22b52f0345d2aaccf22995acf06e84be0ca82ac70 \
  --y 25d76b0fcc7d243c53ca6bb0316590da400587f517e348671349c44883ec079d

  Unmasked x-coordinate (hex): 9221b823bbf244b5d76259886f68b7a9642db26ec6b28ed970dfc714d9f5ea25
  Unmasked y-coordinate (hex): 19771c93a217d6d5debeda167ab11cc4775545ea34c0d26f8f6036b1679c251e

```

## Additional Details

There is a proposal for the EC-OPRF to use ECDSA keys stored in a PEM file instead of user supplied random `s`.

## Contributors

Brian Vohaska