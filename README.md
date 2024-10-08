# AES-CBC Encryption/Decryption Tool

This project is a file encryption and decryption tool that uses the AES-256 algorithm in CBC mode with PKCS7 padding. It allows you to secure files by encrypting them with a password and then decrypting them using the same password.

## Features

- **AES-256 CBC Encryption**: Protects your files with a password using AES-256 in CBC mode.

- **Decryption**: Restores your encrypted files using the same password.

- **Large File Support**: Chunk processing enables encryption and decryption of files of all sizes without using much memory.

## How It Works

- The tool generates a key from the password (concatenated with a random salt) using the SHA-256 algorithm
- Data is encrypted in 8 KB chunks for efficient processing of large files.
- Each chunk uses a unique IV and salt to enhance security.
- The chunks IVs and salts are stored at a dynamic position, calculated by dividing the length of the chunk by the length of the password (not key). This approach provides additional security by making it harder to predict where these elements are stored.

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
./aes-cbc --dec example.txt.enc
```

## Dependencies

This project uses the following Rust crates:

- `aes`: For AES encryption and decryption.
- `cbc`: For CBC mode of operation.
- `rand`: For generating random IVs.
- `sha2`: For hashing the password to generate a key.
- `rpassword`: To securely input your password.

## License

This project is licensed under the GPL-3.0 License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
