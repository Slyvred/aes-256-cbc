# AES-CBC Encryption/Decryption Tool

This project is a file encryption and decryption tool that uses the AES-256 algorithm in CBC mode with PKCS7 padding. It allows you to secure files by encrypting them with a password and then decrypting them using the same password.

## Features

- **AES-256 CBC Encryption**: Protects your files with a password using AES-256 in CBC mode.

- **Decryption**: Restores your encrypted files using the same password.

- **Large File Support**: Chunk processing enables encryption and decryption of files of all sizes without using much memory.

## How It Works

- The tool generates a key derived from the password (with a random salt) using Argon2.
- Data is encrypted in 8 KB chunks for efficient processing of large files.
- The filename is encrypted (with its own IV) to prevent information leakage.
- The IVs (or salts) of the master key and the filename key are stored in the first 32 bytes of the file.
- Each chunk uses a unique IV to enhance security.
- The chunks IVs are stored at a dynamic position, calculated by dividing the length of the chunk by the length of the password (not key). This approach provides additional security by making it harder to predict where these elements are stored.

## Installation

Simply run the following command:
```sh
cargo install --git https://github.com/Slyvred/aes-256-cbc.git

```

## Usage

```sh
./aes-cbc --<mode> <path>
```

- `--<mode>`: Operation mode, either `enc` for encryption or `dec` for decryption.
- `<path>`: Path of the file you want to encrypt/decrypt

### Examples

#### Encrypting a file

```sh
./aes-cbc --enc example.txt
```

#### Decrypting a file

```sh
./aes-cbc --dec 070b5d73320bcb7b5b3ad337f42bf9af
```
With `070b5d73320bcb7b5b3ad337f42bf9af` being the encrypted version of `example.txt`.

## Dependencies

This project uses the following Rust crates:

- `aes`: For AES encryption and decryption.
- `cbc`: For CBC mode of operation.
- `hex`: For encoding and decoding hexadecimal strings.
- `rand`: For generating random IVs.
- `rust-argon2`: To derive the key.
- `rpassword`: To securely input your password.

## License

This project is licensed under the GPL-3.0 License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
