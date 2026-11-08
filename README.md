# pqe

Post-quantum file encryption for any file type (documents, photos, archives). It comes with a command-line tool and a small desktop window, both written in Rust.

**Status: experimental. 

## How it works

- **Key exchange:** hybrid ML-KEM-768 (NIST FIPS 203, post-quantum) + X25519 (classical). An attacker would need to break both.
- **Key derivation:** HKDF-SHA256 mixes both shared secrets and the X25519 public values into a 256-bit file key. The design follows the reasoning behind X-Wing but is not X-Wing compatible.
- **File encryption:** AES-256-GCM in 1 MiB streaming chunks, so large files use almost no memory. The header is authenticated, and decryption fails if the key is wrong or the file was modified. Partial output is deleted on failure.
- **Keys:** the private key is a 32-byte random seed, and everything else is derived from it. The public key is 1,216 bytes.

## Build

Install Rust from https://rustup.rs, then:

    cargo build --release

This produces two programs in `target/release/`: `pqe` (command line) and `pqe-gui` (window).

## Usage

Command line:

    pqe keygen mykey                  # creates mykey.pub and mykey.key
    pqe encrypt photo.jpg mykey.pub   # creates photo.jpg.pqe
    pqe decrypt photo.jpg.pqe mykey.key

Window:

    ./target/release/pqe-gui

Generate a key pair once, drop a file onto the window, pick your key, and click Encrypt or Decrypt. Dropping a `.pqe` file switches it to decrypt mode.

It never overwrites existing files.

## Keys

- `.pub` is the public key. It is used to encrypt, and it is safe to share.
- `.key` is the private key. It is used to decrypt. **Keep it secret and back it up.** If you lose it, your encrypted files cannot be recovered. If someone else gets it, they can decrypt your files.
- Never commit `.key` files to git.

## File format

    "PQE3" | u16 length | X25519 ephemeral key (32 B) | ML-KEM ciphertext (1088 B) | nonce (7 B) | AES-GCM chunks

Overhead is about 1.1 KB per file plus 16 bytes per 1 MiB chunk.

## Limitations

- Not independently audited. The `ml-kem` crate is pre-1.0.
- No digital signatures, so a file doesn't prove who encrypted it.
- The private key file is not password-protected.
- No folder support. Encrypt files one at a time, or zip a folder first.
- Tested only with round trips on macOS.

## License

None yet. All rights reserved until a license is added.
