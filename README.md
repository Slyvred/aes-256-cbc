# AES-CBC Encryption/Decryption Tool

This Rust program provides a command-line tool for encrypting and decrypting files using AES-256 in CBC mode. The tool uses a password to generate a 256-bit key and a random initialization vector (IV) for encryption.

## Usage

```sh
./aes-cbc --<mode> -f <file> -p <password>
```

- `--<mode>`: Operation mode, either `enc` for encryption or `dec` for decryption.
- `-f <file>`: Path to the file to be encrypted or decrypted.
- `-p <password>`: Password used to generate the encryption key.

### Examples

#### Encrypt a file

```sh
./aes-cbc --enc -f example.txt -p mypassword
```

#### Decrypt a file

```sh
./aes-cbc --dec -f example.txt -p mypassword
```

## Dependencies

This project uses the following Rust crates:

- `aes`: For AES encryption and decryption.
- `cbc`: For CBC mode of operation.
- `rand`: For generating random IVs.
- `sha256`: For hashing the password to generate a key.

## Functions

### `main()`

The entry point of the program. It parses command-line arguments, determines the mode (encryption or decryption), and calls the appropriate functions.

### `encrypt(key: [u8; 32], iv: [u8; 16], plaintext: &[u8]) -> Vec<u8>`

Encrypts the plaintext using the provided key and IV.

### `decrypt(key: [u8; 32], iv: [u8; 16], ciphertext: &[u8]) -> Vec<u8>`

Decrypts the ciphertext using the provided key and IV.

### `gen_iv() -> [u8; 16]`

Generates a random IV using `OsRng`.

### `extract_iv(ciphertext: &[u8], password_len: usize) -> ([u8; 16], Vec<u8>)`

Extracts the IV from the ciphertext.

### `append_iv(ciphertext: &[u8], iv: &[u8], password_len: usize) -> Vec<u8>`

Appends the IV to the ciphertext.

### `gen_key_from_password(password: &str) -> [u8; 32]`

Generates a 256-bit key from the provided password using SHA-256.

### `read_file(path: &str) -> Vec<u8>`

Reads the contents of a file and returns it as a `Vec<u8>`.

### `write_file(path: &str, data: &[u8])`

Writes data to a file.

## License

This project is licensed under the GPL-3.0 License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.