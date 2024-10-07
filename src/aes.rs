use crate::helpers;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use helpers::{read_file, write_file};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::thread;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
const NUM_THREADS: usize = 8;

/// In the encrypted file, the IVs and the encrypted extension are stored at the end of the file
struct StoredData {
    key_iv: [u8; 16],
    file_iv: [u8; 16],
    ext_iv: [u8; 16],
    extension: [u8; 16],
}

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
pub fn encrypt_file(file: &str, password_str: &str) {
    let binding = match read_file(file) {
        Ok(binding) => binding,
        Err(err) => {
            println!("{}", err);
            return;
        }
    };

    if binding.is_empty() {
        println!("{} skipping (empty)", file);
        return;
    }

    let plaintext = binding.as_slice();

    let iv = gen_iv();
    let salt = gen_iv();
    let key = gen_key_from_password(password_str, &salt);
    let ciphertext = encrypt(key, iv, plaintext);

    // Free up memory by dropping binding
    drop(binding);

    // Encrypt the extension
    let extension = match std::path::Path::new(file).extension() {
        Some(ext) => ext.to_str().unwrap().as_bytes(),
        None => b"none", // if file has no extension, use "none" as not to break the append_data function
    };

    // let encrypted_extension = encrypt(key, iv, extension);
    let (encrypted_extension, ext_iv) = encrypt_extension(key, extension);

    // Needed data to decrypt the file later
    let stored_data = StoredData {
        key_iv: salt,
        file_iv: iv,
        ext_iv,
        extension: encrypted_extension.try_into().unwrap(),
    };

    // Append the IV and the encrypted extension to the ciphertext
    let final_ciphertext = append_data(&ciphertext, password_str.len(), &stored_data);

    // Free up memory by dropping ciphertext
    drop(ciphertext);

    match write_file(file, &final_ciphertext) {
        Ok(_) => {
            println!("{}", file);
        }
        Err(err) => {
            println!("{}", err);
            return;
        }
    }

    // Rename the file to have a .bin extension
    let path = std::path::Path::new(file);
    let new_file = path.with_extension("bin");
    std::fs::rename(file, new_file).unwrap();
}

/// Encrypt all files in a directory and subdirectories recursively and in parallel
pub fn encrypt_dir(dir: &str, password_str: &str) {
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
        let password_str = password_str.to_string();
        let handle = thread::spawn(move || {
            while let Some(entry) = entries.lock().unwrap().pop() {
                let path = entry.path();
                let path_str = path.to_str().unwrap();

                if path.is_dir() {
                    encrypt_dir(path_str, &password_str);
                } else {
                    encrypt_file(path_str, &password_str);
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

/// Wrapper function to decrypt a file
pub fn decrypt_file(file: &str, password_str: &str) {
    let binding = match read_file(file) {
        Ok(binding) => binding,
        Err(err) => {
            println!("{}", err);
            return;
        }
    };

    if binding.is_empty() {
        println!("{} skipping (empty)", file);
        return;
    }

    let iv_ciphertext = binding.as_slice();

    // Extract the IV and the encrypted extension from the ciphertext
    let (extracted_data, ciphertext) = extract_data(iv_ciphertext, password_str.len());

    let key = gen_key_from_password(password_str, &extracted_data.key_iv);

    // Decrypt the extension
    let decrypted_extension = decrypt(key, extracted_data.ext_iv, &extracted_data.extension);
    let extension = String::from_utf8(decrypted_extension).unwrap();

    // Free up memory by dropping binding
    drop(binding);

    let plaintext = decrypt(key, extracted_data.file_iv, &ciphertext);

    // Free up memory by dropping ciphertext
    drop(ciphertext);

    match write_file(file, &plaintext) {
        Ok(_) => {
            println!("{}", file);
        }
        Err(err) => {
            println!("{}", err);
            return;
        }
    }

    // Rename the file to have its original extension
    let path = std::path::Path::new(file);
    let new_file = path.with_extension(&extension);

    if extension == "none" {
        std::fs::rename(file, path.with_extension("")).unwrap();
    } else {
        std::fs::rename(file, new_file).unwrap();
    }
}

/// Decrypt all files in a directory and subdirectories recursively and in parallel
pub fn decrypt_dir(dir: &str, password_str: &str) {
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
        let password_str = password_str.to_string();
        let handle = thread::spawn(move || {
            while let Some(entry) = entries.lock().unwrap().pop() {
                let path = entry.path();
                let path_str = path.to_str().unwrap();

                if path.is_dir() {
                    decrypt_dir(path_str, &password_str);
                } else {
                    decrypt_file(path_str, &password_str);
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
fn gen_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    match OsRng.try_fill_bytes(&mut iv) {
        Ok(_) => iv,
        Err(_) => panic!("Failed to generate IV"),
    }
}

/// Remove the IV, extension IV and the encrypted extension from the ciphertext so it can be decrypted
fn extract_data(ciphertext: &[u8], password_len: usize) -> (StoredData, Vec<u8>) {
    let file_iv_idx = (ciphertext.len() - 64) / password_len; // -16 * 4 for each field of StoredData
    let ext_iv_idx = file_iv_idx + 16; // Index of the IV of the extension
    let key_iv_idx = ext_iv_idx + 16; // Index of the IV of the key
    let ext_index = key_iv_idx + 16; // Index of the extension

    let file_iv = <[u8; 16]>::try_from(&ciphertext[file_iv_idx..file_iv_idx + 16]).unwrap(); // IV
    let ext_iv = <[u8; 16]>::try_from(&ciphertext[ext_iv_idx..ext_iv_idx + 16]).unwrap(); // IV of extension
    let key_iv = <[u8; 16]>::try_from(&ciphertext[key_iv_idx..key_iv_idx + 16]).unwrap(); // IV of key
    let extension = <[u8; 16]>::try_from(&ciphertext[ext_index..ext_index + 16]).unwrap(); // Extension

    let stored_data = StoredData {
        key_iv,
        file_iv,
        ext_iv,
        extension,
    };

    let mut cleaned_ciphertext = ciphertext.to_vec(); // Copy the ciphertext
    cleaned_ciphertext.drain(file_iv_idx..ext_index + 16); // Remove all the IVs and the extension
    (stored_data, cleaned_ciphertext)
}

/// Append the IV, extension IV and the encrypted extension to the ciphertext
fn append_data(ciphertext: &[u8], password_len: usize, stored_data: &StoredData) -> Vec<u8> {
    // IV is placed at an index calculated by dividing the length of the ciphertext by the password length
    let iv_index = ciphertext.len() / password_len;

    // Create the new ciphertext by collecting the parts
    let mut new_ciphertext = Vec::with_capacity(
        ciphertext.len()
            + stored_data.file_iv.len()
            + stored_data.ext_iv.len()
            + stored_data.key_iv.len()
            + stored_data.extension.len(),
    );
    new_ciphertext.extend_from_slice(&ciphertext[..iv_index]); // Left part
    new_ciphertext.extend_from_slice(&stored_data.file_iv); // File IV
    new_ciphertext.extend_from_slice(&stored_data.ext_iv); // Extension IV
    new_ciphertext.extend_from_slice(&stored_data.key_iv); // Key IV
    new_ciphertext.extend_from_slice(&stored_data.extension); // Extension
    new_ciphertext.extend_from_slice(&ciphertext[iv_index..]); // Right part

    new_ciphertext
}

/// Generate a 32 byte key from a password string concatenated with a random salt
fn gen_key_from_password(password: &str, iv: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let salted_password = [password.as_bytes(), iv].concat();
    hasher.update(&salted_password);
    let result = hasher.finalize();

    // Convert result to 32-byte array
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);

    key
}
