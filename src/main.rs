use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use rand::{rngs::OsRng, RngCore};
use sha256::digest;
use std::env;
use std::io::{Read, Write};
use std::process::exit;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

fn main() {
    // Get password from command line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() != 6 {
        println!("Usage: ./aes-cbc --<mode> -i <path> -p <password>");
        println!("Modes: enc, dec");
        return;
    }

    // Usage: ./aes-cbc --<mode> -i <path> -p <password>
    // Modes: enc, dec
    let mode = &args[1];
    let file = &args[3];

    // Sanitize file path
    let file = file.replace("\"", "");
    let file = file.replace("\'", "");

    // Check if file is directory
    let is_dir = std::fs::metadata(&file).unwrap().is_dir();

    let password_str = &args[5];
    let key = gen_key_from_password(password_str);

    match mode as &str {
        "--enc" => {
            if is_dir {
                // Encrypt all files in directory and subdirectories
                encrypt_dir(key, &file);
            } else {
                let plaintext = read_file(&file);
                let plaintext = plaintext.as_slice();
                let iv = gen_iv();

                let ciphertext = encrypt(key, iv, plaintext);
                let iv_ciphertext = append_iv(&ciphertext, &iv, password_str.len());
                write_file(&file, &iv_ciphertext);
            }
        }
        "--dec" => {
            if is_dir {
                // Decrypt all files in directory and subdirectories
                decrypt_dir(key, &file);
            } else {
                let ciphertext = read_file(&file);
                let ciphertext = ciphertext.as_slice();

                let (iv2, ciphertext2) = extract_iv(ciphertext, password_str.len());
                let plaintext2 = decrypt(key, iv2, &ciphertext2);
                write_file(&file, &plaintext2);
            }
        }
        _ => {
            println!("Invalid mode");
        }
    }
}

fn encrypt(key: [u8; 32], iv: [u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; plaintext.len() + 16];
    let pt_len = plaintext.len();
    buf[..pt_len].copy_from_slice(plaintext);
    let ct = Aes256CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .unwrap();
    ct.to_vec()
}

fn encrypt_dir(key: [u8; 32], dir: &str) {
    let paths = std::fs::read_dir(dir).unwrap();

    for path in paths {
        let path = path.unwrap().path();
        let path_str = path.to_str().unwrap();

        if path.is_dir() {
            encrypt_dir(key, path_str);
        } else {
            let plaintext = read_file(path_str);
            let plaintext = plaintext.as_slice();
            let iv = gen_iv();

            let ciphertext = encrypt(key, iv, plaintext);
            let iv_ciphertext = append_iv(&ciphertext, &iv, key.len());
            write_file(path_str, &iv_ciphertext);
        }
    }
}

fn decrypt(key: [u8; 32], iv: [u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; ciphertext.len()];
    buf[..ciphertext.len()].copy_from_slice(ciphertext);
    let pt = match Aes256CbcDec::new(&key.into(), &iv.into()).decrypt_padded_mut::<Pkcs7>(&mut buf)
    {
        Ok(pt) => pt,
        Err(_) => {
            println!("Failed to decrypt, check key or IV");
            exit(1);
        }
    };

    pt.to_vec()
}

fn decrypt_dir(key: [u8; 32], dir: &str) {
    let paths = std::fs::read_dir(dir).unwrap();

    for path in paths {
        let path = path.unwrap().path();
        let path_str = path.to_str().unwrap();

        if path.is_dir() {
            decrypt_dir(key, path_str);
        } else {
            let ciphertext = read_file(path_str);
            let ciphertext = ciphertext.as_slice();

            let (iv2, ciphertext2) = extract_iv(ciphertext, key.len());
            let plaintext2 = decrypt(key, iv2, &ciphertext2);
            write_file(path_str, &plaintext2);
        }
    }
}

// Generate a random IV using OsRng
fn gen_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    match OsRng.try_fill_bytes(&mut iv) {
        Ok(_) => iv,
        Err(_) => panic!("Failed to generate IV"),
    }
}

// Remove the IV from the ciphertext and return it
fn extract_iv(ciphertext: &[u8], password_len: usize) -> ([u8; 16], Vec<u8>) {
    let mut iv = [0u8; 16];
    // We increased our ciphertext by 16 bytes to store the IV, so we need to subtract 16 bytes to get the IV
    let iv_index = (ciphertext.len() - 16) / password_len;
    iv.copy_from_slice(&ciphertext[iv_index..iv_index + 16]);

    // Remove the IV from the ciphertext
    let mut new_ciphertext = Vec::new();
    new_ciphertext.extend_from_slice(&ciphertext[..iv_index]);
    new_ciphertext.extend_from_slice(&ciphertext[iv_index + 16..]);

    (iv, new_ciphertext)
}

// Append the IV to the ciphertext
fn append_iv(ciphertext: &[u8], iv: &[u8], password_len: usize) -> Vec<u8> {
    // IV is placed at an index calculated by dividing the length of the ciphertext by the password length
    let iv_index = ciphertext.len() / password_len;
    let left_part = &ciphertext[..iv_index];
    let right_part = &ciphertext[iv_index..];

    let mut new_ciphertext = Vec::new();

    new_ciphertext.extend_from_slice(left_part);
    new_ciphertext.extend_from_slice(iv);
    new_ciphertext.extend_from_slice(right_part);

    new_ciphertext
}

fn gen_key_from_password(password: &str) -> [u8; 32] {
    let key_str = password.as_bytes();

    // hash the password using SHA256 to get a 32 byte key no matter the length of the password
    let digest = digest(key_str);

    // convert digest to array of 32 bytes
    let mut key = [0u8; 32];
    key.clone_from_slice(&digest.as_bytes()[..32]);

    key
}

fn read_file(path: &str) -> Vec<u8> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => {
            println!("File not found");
            exit(1);
        }
    };
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    buf
}

fn write_file(path: &str, data: &[u8]) {
    let mut file = match std::fs::File::create(path) {
        Ok(file) => file,
        Err(_) => {
            println!("Failed to create file");
            exit(1);
        }
    };

    file.write_all(data).unwrap();
    println!("{}", path);
}
