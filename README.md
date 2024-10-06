# AES-CBC Encryption/Decryption Tool

This Rust program provides a command-line tool for encrypting and decrypting files using AES-256 in CBC mode. The tool uses a password to generate a 256-bit key and a random initialization vector (IV) for encryption.

## Informations

- The IV is stored at an index calculated by dividing the length of the file by the length of the user submitted password.
- The file extension is encrypted using our key and its own IV that is stored next to our file IV
- The password is hashed using sha256 to ensure a 32 bytes (256bits) key to meet the AES-256 requirements.

## Usage

```sh
./aes-cbc --<mode> -i <path> -p <password>
```

- `--<mode>`: Operation mode, either `enc` for encryption or `dec` for decryption.
- `-i <path>`: Path to the file or directory to be encrypted or decrypted.
- `-p <password>`: Password used to generate the encryption key.

### Examples

#### Encrypt a file

```sh
./aes-cbc --enc -i example.txt -p mypassword
```

#### Decrypt a file

```sh
./aes-cbc --dec -i example.txt -p mypassword
```

## Dependencies

This project uses the following Rust crates:

- `aes`: For AES encryption and decryption.
- `cbc`: For CBC mode of operation.
- `rand`: For generating random IVs.
- `sha256`: For hashing the password to generate a key.

## License

This project is licensed under the GPL-3.0 License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.