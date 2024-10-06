use crate::file;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use file::{read_file, write_file};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::thread;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
const NUM_THREADS: usize = 8;

/// Encrypt a plaintext using AES-256-CBC with PKCS7 padding
fn encrypt(key: [u8; 32], iv: [u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; plaintext.len() + 16];
    let pt_len = plaintext.len();
    buf[..pt_len].copy_from_slice(plaintext);
    let ct = Aes256CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .unwrap();
    ct.to_vec()
}

/// Encrypts the extension of a file with its own IV
fn encrypt_extension(key: [u8; 32], extension: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let iv = gen_iv();
    let ciphertext = encrypt(key, iv, extension);
    (ciphertext, iv)
}

/// Wrapper function to encrypt a file
pub fn encrypt_file(file: &str, password_len: usize, key: [u8; 32]) {
    let binding = read_file(file);

    if binding.is_empty() {
        println!("File not found");
        return;
    }

    let plaintext = binding.as_slice();

    let iv = gen_iv();
    let ciphertext = encrypt(key, iv, plaintext);

    // Free up memory by dropping binding
    drop(binding);

    // Encrypt the extension
    let extension = file.split('.').last().unwrap().as_bytes();
    // let encrypted_extension = encrypt(key, iv, extension);
    let (encrypted_extension, ext_iv) = encrypt_extension(key, extension);

    // Append the IV and the encrypted extension to the ciphertext
    let final_ciphertext = append_data(
        &ciphertext,
        &iv,
        password_len,
        &encrypted_extension,
        &ext_iv,
    );

    // Free up memory by dropping ciphertext
    drop(ciphertext);

    write_file(file, &final_ciphertext);

    // Rename the file to have a .bin extension
    let path = std::path::Path::new(file);
    let new_file = path.with_extension("bin");
    std::fs::rename(file, new_file).unwrap();
}

/// Encrypt all files in a directory and subdirectories recursively and in parallel
pub fn encrypt_dir(password_len: usize, key: [u8; 32], dir: &str) {
    let paths = match std::fs::read_dir(dir) {
        Ok(paths) => paths,
        Err(_) => {
            println!("Directory not found");
            return;
        }
    };

    let entries: Vec<_> = paths.filter_map(Result::ok).collect();
    let entries = Arc::new(Mutex::new(entries));
    let mut handles = vec![];

    for _ in 0..NUM_THREADS {
        let entries = Arc::clone(&entries);
        let handle = thread::spawn(move || {
            while let Some(entry) = entries.lock().unwrap().pop() {
                let path = entry.path();
                let path_str = path.to_str().unwrap();

                if path.is_dir() {
                    encrypt_dir(password_len, key, path_str);
                } else {
                    encrypt_file(path_str, password_len, key);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

/// Decrypt a ciphertext using AES-256-CBC with PKCS7 padding
pub fn decrypt(key: [u8; 32], iv: [u8; 16], ciphertext: &[u8]) -> Vec<u8> {
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

/// Wrapper function to decrypt a file
pub fn decrypt_file(file: &str, password_len: usize, key: [u8; 32]) {
    let binding = read_file(file);

    if binding.is_empty() {
        println!("File not found");
        return;
    }

    let iv_ciphertext = binding.as_slice();

    // Extract the IV and the encrypted extension from the ciphertext
    let (iv, ext_iv, extension, ciphertext) = extract_data(iv_ciphertext, password_len);

    // Decrypt the extension
    let decrypted_extension = decrypt(key, ext_iv, &extension);
    let extension = String::from_utf8(decrypted_extension).unwrap();

    // Free up memory by dropping binding
    drop(binding);

    let plaintext = decrypt(key, iv, &ciphertext);

    // Free up memory by dropping ciphertext
    drop(ciphertext);

    write_file(file, &plaintext);

    // Rename the file to have its original extension
    let path = std::path::Path::new(file);
    let new_file = path.with_extension(extension);
    std::fs::rename(file, new_file).unwrap();
}

/// Decrypt all files in a directory and subdirectories recursively and in parallel
pub fn decrypt_dir(key: [u8; 32], password_len: usize, dir: &str) {
    let paths = match std::fs::read_dir(dir) {
        Ok(paths) => paths,
        Err(_) => {
            println!("Directory not found");
            return;
        }
    };

    let entries: Vec<_> = paths.filter_map(Result::ok).collect();
    let entries = Arc::new(Mutex::new(entries));
    let mut handles = vec![];

    for _ in 0..NUM_THREADS {
        let entries = Arc::clone(&entries);
        let handle = thread::spawn(move || {
            while let Some(entry) = entries.lock().unwrap().pop() {
                let path = entry.path();
                let path_str = path.to_str().unwrap();

                if path.is_dir() {
                    decrypt_dir(key, password_len, path_str);
                } else {
                    decrypt_file(path_str, password_len, key);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

/// Generate a random IV using OsRng
pub fn gen_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    match OsRng.try_fill_bytes(&mut iv) {
        Ok(_) => iv,
        Err(_) => panic!("Failed to generate IV"),
    }
}

/// Remove the IV, extension IV and the encrypted extension from the ciphertext so it can be decrypted
fn extract_data(ciphertext: &[u8], password_len: usize) -> ([u8; 16], [u8; 16], [u8; 16], Vec<u8>) {
    let iv_index = (ciphertext.len() - 48) / password_len; // -16 for IV and -16 for extension and -16 for IV of extension
    let ext_iv_index = iv_index + 16; // Index of the IV of the extension
    let ext_index = ext_iv_index + 16; // Index of the extension

    let iv = <[u8; 16]>::try_from(&ciphertext[iv_index..iv_index + 16]).unwrap(); // IV
    let ext_iv = <[u8; 16]>::try_from(&ciphertext[ext_iv_index..ext_iv_index + 16]).unwrap(); // IV of extension
    let extension = <[u8; 16]>::try_from(&ciphertext[ext_index..ext_index + 16]).unwrap(); // Extension

    let mut new_ciphertext = ciphertext.to_vec(); // Copy the ciphertext
    new_ciphertext.drain(iv_index..ext_index + 16); // Remove IV and extension
    (iv, ext_iv, extension, new_ciphertext)
}

/// Append the IV, extension IV and the encrypted extension to the ciphertext
fn append_data(
    ciphertext: &[u8],
    iv: &[u8],
    password_len: usize,
    extension: &[u8],
    ext_iv: &[u8],
) -> Vec<u8> {
    // IV is placed at an index calculated by dividing the length of the ciphertext by the password length
    let iv_index = ciphertext.len() / password_len;

    // Create the new ciphertext by collecting the parts
    let mut new_ciphertext =
        Vec::with_capacity(ciphertext.len() + iv.len() + ext_iv.len() + extension.len());
    new_ciphertext.extend_from_slice(&ciphertext[..iv_index]); // Left part
    new_ciphertext.extend_from_slice(iv); // IV
    new_ciphertext.extend_from_slice(ext_iv); // Extension IV
    new_ciphertext.extend_from_slice(extension); // Extension
    new_ciphertext.extend_from_slice(&ciphertext[iv_index..]); // Right part

    new_ciphertext
}

/// Generate a 32 byte key from a password string
pub fn gen_key_from_password(password: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();

    // Convert result to 32-byte array
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);

    key
}
