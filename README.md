# Frost.rs Python Bindings

This library is a port of [frost.rs](https://github.com/ZcashFoundation/frost.rs) written by the Zcash Foundation for Python 3.10 or Python 3.11. It provides bindings to the Rust library for performing various cryptographic operations, including distributed key generation (DKG), nonce generation, and signing signature.

## Installation

To install the library, run the following command:

```bash
$ pip install frost_rs
```

- it's recommended to run the command in virtual environment

## Supported Platforms

The current supported operating systems are x86-64 Linux and Windows. If you want to use this library on an unsupported platform, you need to install the Rust compiler on your device by running:

```bash
$ sudo apt install cargo
```

After installing Cargo, you can install the package using `pip`. It will download the source distribution and build it for your platform.

For more information on installing Rust, visit the [official Rust website](https://www.rust-lang.org/learn/get-started).

## Features

This library supports the following elliptic curves:

- secp256k1
- ed448
- ed25519
- p256
- ristretto255

**All outputs are base64url encoded strings and not encrypted!!**

## Benchmarks

The following benchmarks show the performance of the library for different values of T (number of parties) and N (number of nodes) on local machine with AMD 5600x.

### T=7, N=10

| Library                | DKG (sec) | Nonce Gen (sec/node) | Sign (sec) |
| ---------------------- | --------- | -------------------- | ---------- |
| `utility_secp256k1`    | 0.098374  | 0.001000             | 0.006513   |
| `utility_ed448`        | 0.978722  | 0.012515             | 0.087149   |
| `utility_ed25519`      | 0.105699  | 0.001000             | 0.011518   |
| `utility_p256`         | 0.247465  | 0.002572             | 0.011449   |
| `utility_ristretto255` | 0.061611  | 0.001000             | 0.006510   |

### T=15, N=20

| Library                | DKG (sec) | Nonce Gen (sec/node) | Sign (sec) |
| ---------------------- | --------- | -------------------- | ---------- |
| `utility_secp256k1`    | 0.761673  | 0.002511             | 0.020761   |
| `utility_ed448`        | 7.640174  | 0.028124             | 0.316123   |
| `utility_ed25519`      | 0.828624  | 0.002000             | 0.038753   |
| `utility_p256`         | 1.769641  | 0.006398             | 0.039469   |
| `utility_ristretto255` | 0.489567  | 0.001509             | 0.017441   |

### T=25, N=30

| Library                | DKG (sec) | Nonce Gen (sec/node) | Sign (sec) |
| ---------------------- | --------- | -------------------- | ---------- |
| `utility_secp256k1`    | 2.598118  | 0.004004             | 0.044556   |
| `utility_ed448`        | 27.671697 | 0.036910             | 0.691816   |
| `utility_ed25519`      | 2.879805  | 0.004503             | 0.083431   |
| `utility_p256`         | 6.378291  | 0.009511             | 0.085119   |
| `utility_ristretto255` | 1.672220  | 0.003009             | 0.037045   |
