use crate::file;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use file::{read_file, write_file};
use rand::{rngs::OsRng, RngCore};
use sha256::digest;
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::thread;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
const NUM_THREADS: usize = 8;

pub fn encrypt(key: [u8; 32], iv: [u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; plaintext.len() + 16];
    let pt_len = plaintext.len();
    buf[..pt_len].copy_from_slice(plaintext);
    let ct = Aes256CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .unwrap();
    ct.to_vec()
}

pub fn encrypt_dir(key: [u8; 32], dir: &str) {
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
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

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

pub fn decrypt_dir(key: [u8; 32], dir: &str) {
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
                    decrypt_dir(key, path_str);
                } else {
                    let ciphertext = read_file(path_str);
                    let ciphertext = ciphertext.as_slice();

                    let (iv2, ciphertext2) = extract_iv(ciphertext, key.len());
                    let plaintext2 = decrypt(key, iv2, &ciphertext2);
                    write_file(path_str, &plaintext2);
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}

// Generate a random IV using OsRng
pub fn gen_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    match OsRng.try_fill_bytes(&mut iv) {
        Ok(_) => iv,
        Err(_) => panic!("Failed to generate IV"),
    }
}

// Remove the IV from the ciphertext and return it
pub fn extract_iv(ciphertext: &[u8], password_len: usize) -> ([u8; 16], Vec<u8>) {
    let iv_index = (ciphertext.len() - 16) / password_len;
    let iv = <[u8; 16]>::try_from(&ciphertext[iv_index..iv_index + 16]).unwrap();
    let mut new_ciphertext = ciphertext.to_vec();
    new_ciphertext.drain(iv_index..iv_index + 16);
    (iv, new_ciphertext)
}

// Append the IV to the ciphertext
pub fn append_iv(ciphertext: &[u8], iv: &[u8], password_len: usize) -> Vec<u8> {
    // IV is placed at an index calculated by dividing the length of the ciphertext by the password length
    let iv_index = ciphertext.len() / password_len;

    // Create the new ciphertext by collecting the parts
    let mut new_ciphertext = Vec::with_capacity(ciphertext.len() + iv.len());
    new_ciphertext.extend_from_slice(&ciphertext[..iv_index]); // Left part
    new_ciphertext.extend_from_slice(iv); // IV
    new_ciphertext.extend_from_slice(&ciphertext[iv_index..]); // Right part

    new_ciphertext
}

pub fn gen_key_from_password(password: &str) -> [u8; 32] {
    let key_str = password.as_bytes();

    // hash the password using SHA256 to get a 32 byte key no matter the length of the password
    let digest = digest(key_str);

    // convert digest to array of 32 bytes
    let mut key = [0u8; 32];
    key.clone_from_slice(&digest.as_bytes()[..32]);

    key
}
