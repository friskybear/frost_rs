# Frost.rs Python Bindings

This library is a port of [frost.rs](https://github.com/ZcashFoundation/frost.rs) written by the Zcash Foundation for Python 3.8-12. It provides bindings to the Rust library for performing various cryptographic operations, including distributed key generation (DKG), nonce generation, and signing signature blazingly fast.

## Installation

To install the library, run the following command:

```bash
$ pip install frost_rs
```

- it's recommended to run the command in a virtual environment

## Supported Platforms

If you could not install the library due to unsupported Operating System , you can install the Rust compiler on your device by running:

```bash
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

After installing Rust, you can install the package using the same pip command

It will download the source distribution and build it for your platform.

For more information on installing Rust, visit the [official Rust website](https://www.rust-lang.org/learn/get-started).

## Features

This library supports the following elliptic curves:

- secp256k1
- ed448
- ed25519
- p256
- ristretto255

**All outputs are base64url encoded strings and not encrypted!!**
**Note: In version 0.1.3 and above, the output of Dkg:round 2 will be automatically encrypted. Therefore, any output that is not marked as secret can be broadcasted.**

## guide

here is a example of how to use the library to make a signature and verify it

```python
# put utility_ before elliptic curves
from frost import utility_secp256k1 as frost

min_signers = 7
max_signers = 10
message = "hello Frost_rs"
# get an identifier (chance of collision is 1/2^64)
identifiers: str = [frost.get_id() for _ in range(max_signers)]

# run the three round protocol to get the key

round1_secret_packages: dict[str:str] = {}
round1_public_packages: dict[str:str] = {}
# every one sends their round public package to each other and use it in round 2
for id in identifiers:
    (round1_secret_packages[id], round1_public_packages[id]) = frost.round1(
        id, min_signers, max_signers)

round2_secret_packages: dict[str:str] = {}
round2_public_packages: dict[str:dict[str:str]] = {}


# in round 2 every one make a dict (identifier to package) and each sends the package to each user with help of identifier
for id in identifiers:
    round1_received_packages = {
        key: value for key, value in round1_public_packages.items() if key != id}
    (round2_secret_packages[id], round2_public_packages[id]) = frost.round2(
        round1_secret_packages[id], round1_received_packages)

key_packages: dict[str:str] = {}
pubkey_packages: dict[str:str] = {}

# every one will get their key package and the group public key
for id in identifiers:
    round1_received_packages = {
        key: value for key, value in round1_public_packages.items() if key != id}
    round2_received_packages = {
        k: v[id] for k, v in round2_public_packages.items() if id in v}
    (key_packages[id], pubkey_packages[id]) = frost.round3(
        round2_secret_packages[id], round1_received_packages, round2_received_packages)
nonces: dict[str:str] = {}
commitments: dict[str:str] = {}

# nonce generation can be preprocessed
# commitment should be sent to others
for id in identifiers:
    (nonces[id], commitments[id]) = frost.preprocess(key_packages[id])
# in this example no participant leaves so it acts as normal multi sig
signature_shares: dict[str:str] = {}
# every one sign the message and send the result to the person who aggregated the signature
for id in identifiers:
    signature_shares[id] = frost.sign(
        message, commitments, nonces[id], key_packages[id])
# after reciveing the shares aggregator will make the signature and serialize it
group_signature = frost.aggregate(
    message, commitments, signature_shares, pubkey_packages[identifiers[0]])

# verify(message[bytes] - pubkey[string] - signature[string])-> bool
# any one can now verify the signature if they have the access to the parameters
verification_result = frost.verify(
    message, pubkey_packages[identifiers[0]], group_signature)
```

## Benchmarks

The following benchmarks show the performance of the library for different values of T (number of parties) and N (number of nodes) on local machine with AMD 5600x.

### T=7, N=10

| Library                | DKG (sec) | Nonce Gen (sec/node) | Sign (sec) |
| ---------------------- | --------- | -------------------- | ---------- |
| `utility_secp256k1`    | 0.110016  | 0.000100             | 0.005999   |
| `utility_ed448`        | 0.996042  | 0.001301             | 0.086805   |
| `utility_ed25519`      | 0.109749  | 0.000200             | 0.010864   |
| `utility_p256`         | 0.247094  | 0.000288             | 0.010576   |
| `utility_ristretto255` | 0.066160  | 0.000100             | 0.005664   |

### T=15, N=20

| Library                | DKG (sec) | Nonce Gen (sec/node) | Sign (sec) |
| ---------------------- | --------- | -------------------- | ---------- |
| `utility_secp256k1`    | 0.819098  | 0.000150             | 0.021002   |
| `utility_ed448`        | 7.780945  | 0.001188             | 0.316400   |
| `utility_ed25519`      | 0.828922  | 0.000150             | 0.042004   |
| `utility_p256`         | 1.825327  | 0.000297             | 0.039655   |
| `utility_ristretto255` | 0.491067  | 0.000100             | 0.016765   |

### T=25, N=30

| Library                | DKG (sec) | Nonce Gen (sec/node) | Sign (sec) |
| ---------------------- | --------- | -------------------- | ---------- |
| `utility_secp256k1`    | 2.931058  | 0.000162             | 0.046715   |
| `utility_ed448`        | 27.882355 | 0.001225             | 0.679499   |
| `utility_ed25519`      | 3.050586  | 0.000133             | 0.083511   |
| `utility_p256`         | 6.487219  | 0.000317             | 0.083003   |
| `utility_ristretto255` | 1.803785  | 0.000100             | 0.037506   |
