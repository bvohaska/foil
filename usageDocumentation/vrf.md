# RSA Key Generation

Foil can generate and verify VRF messages based on <https://eprint.iacr.org/2017/099.pdf>

## Usage

```bash

$: foil vrf [type] [operation] [path to input] [flags]

```

### Available Types

`gen` - Generate a VRF proof and H(proof) aka Beta

`ver` - Verify a given VRF proof and associated Beta

### Available Flags

`--ecc` - Use an EC-based VRF (P-256 w/ SHA-256)

`--rsa` - Use a RSA-based VRF

### Support Flags

`--alpha` - The string to be VRF'd aka VRF input

`--beta` - The hash of the VRF proof, H(proof)

`--proof` - The VRF output aka VRF proof

### Examples

RSA-based VRF generation,

```bash

$: foil vrf gen --rsa --alpha \"ET phones home\" --in testPriv.pem

  RSA-VRF Proof           (hex): 273e18815bb254c8ca2431189fffc3ae186c8e327653a889777a148d60a2782834ef2820f5c26362032d21409615658685406960682d76b8d5fbc6c9595b5c4591ace50dafc3c9de175c2f3930ed69a4e79e48108d3818156d9cbb6902857ad9f89d4430dc2fafadcea17de600e830c1ee66fc4b9cefc71455dafe063101af41e44a23fc6e1b41b749b2affa2607c2bfff084969200cfaa7c2cf588a12f5184e56268ee8b8e0deef8202a98b964beb1fde376a75b3017d4867dc3fa66f8548b625c9db3517d6eca99ad3662670fd0471be6eeff5d9e904150e0fb223eff50bca29a506aa0d10360e65641579a306ec9accbe299df464fa7ea8f4d75aa160824b
  RSA-VRF Beta - H(Proof) (hex): 9fca5415b04b2e9f896594f1bfce4d01cbd6130b157edefd9e9f4f5976a42413

```

RSA-based VRF verification,

```bash

$: foil vrf ver --rsa --alpha \"ET phones home\" --in testPub.pem \
  --beta 9fca5415b04b2e9f896594f1bfce4d01cbd6130b157edefd9e9f4f5976a42413 \
  --proof 273e18815bb254c8ca2431189fffc3ae186c8e327653a889777a148d60a2782834ef2820f5c26362032d21409615658685406960682d76b8d5fbc6c9595b5c4591ace50dafc3c9de175c2f3930ed69a4e79e48108d3818156d9cbb6902857ad9f89d4430dc2fafadcea17de600e830c1ee66fc4b9cefc71455dafe063101af41e44a23fc6e1b41b749b2affa2607c2bfff084969200cfaa7c2cf588a12f5184e56268ee8b8e0deef8202a98b964beb1fde376a75b3017d4867dc3fa66f8548b625c9db3517d6eca99ad3662670fd0471be6eeff5d9e904150e0fb223eff50bca29a506aa0d10360e65641579a306ec9accbe299df464fa7ea8f4d75aa160824b

  VRF Proof & Beta are valid

```

Note that a salt `s` can be provided. If not supplied, a new `s` will be generated.

EC-based VRF generation,

```bash

$: foil vrf gen --rsa --alpha \"ET phones home\" --in testPriv.pem

  EC-VRF Proof - x, y, c, s (hex): d90d69b3db6f7ff49cb6953edc72af24a542ae002229a3e588eb5ca5bde7c1ed, 6e17e1c53e3c65ee8c8d9081ab9005e3b298c2bc9470e284ebe6eeebf8fd29e7, eb8787f1f30363d69419a1821a7ac09be00628515b36fed70060d969d1cc04d5, c0a365a34e61fc4b39ef2684648de6f7dda4f73cc43e814ad34ad0a0eb1c8385
  EC-VRF Beta H(Proof) (hex): 8acb6129eacd716274fa2a4bb07c7376e9f6d689fa6f3edb912b1284c6799c4e

```

EC-based VRF verification,

```bash

$: foil vrf ver --ecc --alpha \"ET phones home\" --in testPub.pem \
  --beta 8acb6129eacd716274fa2a4bb07c7376e9f6d689fa6f3edb912b1284c6799c4e \
  --proof \"d90d69b3db6f7ff49cb6953edc72af24a542ae002229a3e588eb5ca5bde7c1ed, 6e17e1c53e3c65ee8c8d9081ab9005e3b298c2bc9470e284ebe6eeebf8fd29e7, eb8787f1f30363d69419a1821a7ac09be00628515b36fed70060d969d1cc04d5, c0a365a34e61fc4b39ef2684648de6f7dda4f73cc43e814ad34ad0a0eb1c8385\"

VRF Proof & Beta are valid
```

## Additional Details

EC-VRF Proof output will change based on the choice of random secret `k`. As a result, VRF output will change as expected.

## Contributors

Brian Vohaska