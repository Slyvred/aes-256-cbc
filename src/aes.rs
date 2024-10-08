use crate::helpers;
use aes::cipher::inout::PadError;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use helpers::print_progress_bar;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::io::{BufReader, BufWriter, Read, Seek, Write};
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
const ENC_BUFFER_SIZE: usize = 8192;
const DEC_BUFFER_SIZE: usize = 8192 + 32 + 16; // 8192 + 32 (= StoredData) + 16 (16 = AES-256 block size)

/// In the encrypted file, the IVs and the encrypted extension are stored at the end of the file
struct StoredData {
    password_salt: [u8; 16],
    chunk_iv: [u8; 16],
}

/// Encrypt a plaintext using AES-256-CBC with PKCS7 padding
fn encrypt(key: [u8; 32], iv: [u8; 16], plaintext: &[u8]) -> Result<Vec<u8>, PadError> {
    let mut buf = vec![0u8; plaintext.len() + 16];
    let pt_len = plaintext.len();
    buf[..pt_len].copy_from_slice(plaintext);
    match Aes256CbcEnc::new(&key.into(), &iv.into()).encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len) {
        Ok(ct) => Ok(ct.to_vec()),
        Err(e) => Err(e),
    }
}

/// Wrapper function to encrypt a file
pub fn encrypt_file(path: &str, password_str: &str) {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => {
            println!("File not found");
            return;
        }
    };

    let output_file = match std::fs::File::create(format!("{}.enc", path)) {
        Ok(file) => file,
        Err(_) => {
            println!("Failed to create output file");
            return;
        }
    };

    let mut reader = BufReader::new(file);
    let mut writer = BufWriter::new(output_file);
    let mut buf = [0u8; ENC_BUFFER_SIZE];
    let file_size = std::fs::metadata(path).unwrap().len();

    while let Ok(bytes_read) = reader.read(&mut buf) {
        if bytes_read == 0 {
            break;
        }

        let chunk_salt = gen_iv();
        let chunk_key = gen_key_from_password(password_str, &chunk_salt);
        let chunk_iv = gen_iv();

        let ciphertext = match encrypt(chunk_key, chunk_iv, &buf[..bytes_read]) {
            Ok(ct) => ct,
            Err(e) => {
                println!("Failed to encrypt chunk: {:?}", e);
                return;
            }
        };

        let stored_data = StoredData {
            password_salt: chunk_salt,
            chunk_iv,
        };

        let final_ciphertext = append_data(&ciphertext, password_str.len(), &stored_data);
        writer.write_all(&final_ciphertext).unwrap();

        print_progress_bar(
            reader.stream_position().unwrap() as f64 / file_size as f64,
            path,
        );
    }

    // Print a newline after the progress bar
    println!();
}

/// Decrypt a ciphertext using AES-256-CBC with PKCS7 padding
fn decrypt(key: [u8; 32], iv: [u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, &str> {
    let mut buf = vec![0u8; ciphertext.len()];
    buf[..ciphertext.len()].copy_from_slice(ciphertext);

    match Aes256CbcDec::new(&key.into(), &iv.into()).decrypt_padded_mut::<Pkcs7>(&mut buf) {
        Ok(pt) => Ok(pt.to_vec()),
        Err(_) => Err("Wrong password"),
    }
}

/// Wrapper function to decrypt a file
pub fn decrypt_file(path: &str, password_str: &str) {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => {
            println!("File not found");
            return;
        }
    };

    let output_file = match std::fs::File::create(path.replace(".enc", "")) {
        Ok(file) => file,
        Err(_) => {
            println!("Failed to create output file");
            return;
        }
    };

    let mut reader = BufReader::new(file);
    let mut writer = BufWriter::new(output_file);
    let mut buf = [0u8; DEC_BUFFER_SIZE];

    let file_size = std::fs::metadata(path).unwrap().len();
    let num_chunks = file_size / DEC_BUFFER_SIZE as u64; // Number of 8KB chunks
    let remaining_bytes = file_size % DEC_BUFFER_SIZE as u64; // Remaining bytes, that don't fit in a chunk

    for _ in 0..num_chunks {
        reader.read_exact(&mut buf).unwrap();

        let (stored_data, ciphertext) = extract_data(&buf, password_str.len());
        let chunk_key = gen_key_from_password(password_str, &stored_data.password_salt);

        let plaintext = match decrypt(chunk_key, stored_data.chunk_iv, &ciphertext) {
            Ok(pt) => pt,
            Err(e) => {
                println!("Failed to decrypt chunk: {:?}", e);
                return;
            }
        };

        writer.write_all(&plaintext).unwrap();

        print_progress_bar(
            reader.stream_position().unwrap() as f64 / file_size as f64,
            path,
        );
    }

    // Process remaining bytes, if any
    if remaining_bytes > 0 {
        let mut last_buf = vec![0u8; remaining_bytes as usize];
        reader.read_exact(&mut last_buf).unwrap();

        let (stored_data, ciphertext) = extract_data(&last_buf, password_str.len());
        let chunk_key = gen_key_from_password(password_str, &stored_data.password_salt);

        let plaintext = match decrypt(chunk_key, stored_data.chunk_iv, &ciphertext) {
            Ok(pt) => pt,
            Err(e) => {
                println!("Failed to decrypt chunk: {:?}", e);
                return;
            }
        };

        writer.write_all(&plaintext).unwrap();
    }

    // Print a newline after the progress bar
    println!();
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
    let file_iv_idx = (ciphertext.len() - 32) / password_len; // -16 * 2 for each field of StoredData
    let key_iv_idx = file_iv_idx + 16; // Index of the IV of the key

    let chunk_iv = <[u8; 16]>::try_from(&ciphertext[file_iv_idx..file_iv_idx + 16]).unwrap(); // IV
    let password_salt = <[u8; 16]>::try_from(&ciphertext[key_iv_idx..key_iv_idx + 16]).unwrap(); // password salts

    let stored_data = StoredData {
        password_salt,
        chunk_iv,
    };

    // Copy the ciphertext
    let mut cleaned_ciphertext = ciphertext.to_vec();

    cleaned_ciphertext.drain(file_iv_idx..key_iv_idx + 16); // Remove all the IVs and the extension
    (stored_data, cleaned_ciphertext)
}

/// Append the IV, extension IV and the encrypted extension to the ciphertext
fn append_data(ciphertext: &[u8], password_len: usize, stored_data: &StoredData) -> Vec<u8> {
    // IV is placed at an index calculated by dividing the length of the ciphertext by the password length
    let iv_index = ciphertext.len() / password_len;

    // Create the new ciphertext by collecting the parts
    let mut new_ciphertext = Vec::with_capacity(
        ciphertext.len() + 32, // 16 * 4 for each field of StoredData
    );
    new_ciphertext.extend_from_slice(&ciphertext[..iv_index]); // Left part
    new_ciphertext.extend_from_slice(&stored_data.chunk_iv); // IV of current chunk
    new_ciphertext.extend_from_slice(&stored_data.password_salt); // password salt of current chunk
    new_ciphertext.extend_from_slice(&ciphertext[iv_index..]); // Right part

    new_ciphertext
}

/// Generate a 32 byte key from a password string concatenated with a random salt
fn gen_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let salted_password = [password.as_bytes(), salt].concat();
    hasher.update(&salted_password);
    let result = hasher.finalize();

    // Convert result to 32-byte array
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);

    key
}
