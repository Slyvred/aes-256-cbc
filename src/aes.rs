use crate::helpers;
use aes::cipher::block_padding::UnpadError;
use aes::cipher::inout::PadError;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use argon2::{self, Config};
use helpers::print_progress_bar;
use rand::{rngs::OsRng, RngCore};
use std::io::{BufReader, BufWriter, Read, Seek, Write};

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

const STORED_DATA_SIZE: usize = 16; // Chunk IV Size
const ENC_BUFFER_SIZE: usize = 8192;
const DEC_BUFFER_SIZE: usize = ENC_BUFFER_SIZE + STORED_DATA_SIZE + 16; // 8192 + 16 (= StoredData) + 16 (16 = AES-256 block size)

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
pub fn encrypt_file(path: &str, password_str: &str, delete: bool) -> Result<(), &'static str> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return Err("Failed to open file"),
    };

    // Encrypt filename and extension
    let mut filename = path.split('/').last().unwrap();

    // If the split doesn't work, it means we're on Windows
    // We split on backslashes instead
    if filename == path {
        filename = path.split('\\').last().unwrap();
    }

    let filename_salt = gen_iv();
    let filename_key = gen_key_from_password(password_str, &filename_salt);
    let filename_iv = gen_iv();

    let encrypted_filename = match encrypt(filename_key, filename_iv, filename.as_bytes()) {
        Ok(ct) => ct,
        Err(_) => return Err("Filename encryption failed"),
    };

    // Convert encrypted filename to hex string
    let encrypted_filename = hex::encode(encrypted_filename);
    let output_path = path.replace(filename, &encrypted_filename);

    println!("Encrypting {} to {}", path, output_path);

    let output_file = match std::fs::File::create(output_path) {
        Ok(file) => file,
        Err(_) => return Err("Failed to create output file"),
    };

    let mut reader = BufReader::new(file);
    let mut writer = BufWriter::new(output_file);
    let mut buf = [0u8; ENC_BUFFER_SIZE];
    let file_size = std::fs::metadata(path).unwrap().len();

    // Generate a random salt and derive a key from the password
    let salt = gen_iv();
    let key = gen_key_from_password(password_str, &salt);

    // Write the salts to the beginning of the output file
    // Header: [filename_salt][filename_iv][salt] = 16 + 16 + 16 = 48 bytes
    writer.write_all(&filename_salt).unwrap();
    writer.write_all(&filename_iv).unwrap();
    writer.write_all(&salt).unwrap();

    while let Ok(bytes_read) = reader.read(&mut buf) {
        if bytes_read == 0 {
            break;
        }
        let chunk_iv = gen_iv();

        let ciphertext = match encrypt(key, chunk_iv, &buf[..bytes_read]) {
            Ok(ct) => ct,
            Err(_) => return Err("Encryption failed"),
        };

        // Chunk = IV + Ciphertext
        writer.write_all(&chunk_iv).unwrap();
        writer.write_all(&ciphertext).unwrap();

        print_progress_bar(
            reader.stream_position().unwrap() as f64 / file_size as f64,
            path,
        );
    }

    // Print a newline after the progress bar
    println!();

    if delete {
        match std::fs::remove_file(path) {
            Ok(_) => (),
            Err(_) => return Err("Failed to delete original file"),
        }
    }

    Ok(())
}

/// Decrypt a ciphertext using AES-256-CBC with PKCS7 padding
fn decrypt(key: [u8; 32], iv: [u8; 16], ciphertext: &[u8]) -> Result<Vec<u8>, UnpadError> {
    let mut buf = vec![0u8; ciphertext.len()];
    buf[..ciphertext.len()].copy_from_slice(ciphertext);

    match Aes256CbcDec::new(&key.into(), &iv.into()).decrypt_padded_mut::<Pkcs7>(&mut buf) {
        Ok(pt) => Ok(pt.to_vec()),
        Err(e) => Err(e),
    }
}

/// Wrapper function to decrypt a file
pub fn decrypt_file(path: &str, password_str: &str, delete: bool) -> Result<(), &'static str> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return Err("Failed to open file"),
    };

    let mut encrypted_filename_str = path.split('/').last().unwrap();

    // If the split doesn't work, it means we're on Windows
    // We split on backslashes instead
    if encrypted_filename_str == path {
        encrypted_filename_str = path.split('\\').last().unwrap();
    }

    let encrypted_filename = match hex::decode(encrypted_filename_str) {
        Ok(hex) => hex,
        Err(_) => return Err("Failed to decode filename hex"),
    };

    // Read the salts and the IV from the beginning of the file
    // Acts like a header for the encrypted file
    let mut file_header = [0u8; 48];
    let mut reader = BufReader::new(file);

    // Read the salt from the first 48 bytes of the file
    match reader.read_exact(&mut file_header) {
        Ok(_) => (),
        Err(_) => return Err("Failed to read salts, are you sure this file is encrypted?"),
    }

    // The first 16 bytes are the salt of the filename key
    // The next 16 bytes are the IV used to encrypt the filename
    // The last 16 bytes are the salt of the data key
    // Header: [filename_salt][filename_iv][salt] = 16 + 16 + 16 = 48 bytes
    let filename_salt: [u8; 16] = file_header[..16].try_into().unwrap();
    let filename_iv: [u8; 16] = file_header[16..32].try_into().unwrap();
    let salt: [u8; 16] = file_header[32..].try_into().unwrap();

    let filename_key = gen_key_from_password(password_str, &filename_salt);

    let filename = match decrypt(filename_key, filename_iv, &encrypted_filename) {
        Ok(pt) => pt,
        Err(_) => return Err("Wrong password"),
    };

    let filename = String::from_utf8(filename).unwrap();
    let output_path = path.replace(encrypted_filename_str, &filename);

    println!("Decrypting {} to {}", path, output_path);

    let output_file = match std::fs::File::create(output_path) {
        Ok(file) => file,
        Err(_) => return Err("Failed to create output file"),
    };

    let mut writer = BufWriter::new(output_file);
    let mut buf = [0u8; DEC_BUFFER_SIZE];

    let file_size = std::fs::metadata(path).unwrap().len() - 48; // -48 bytes for the header size
    let num_chunks = file_size / DEC_BUFFER_SIZE as u64; // Number of 8KB chunks, -16 for the salt
    let remaining_bytes = file_size % DEC_BUFFER_SIZE as u64; // Remaining bytes, that don't fit in a chunk

    // Derive the key from the password and the salt
    let key = gen_key_from_password(password_str, &salt);

    for _ in 0..num_chunks {
        reader.read_exact(&mut buf).unwrap();

        let chunk_iv: [u8; 16] = buf[..16].try_into().unwrap();
        let ciphertext = &buf[16..];

        let plaintext = match decrypt(key, chunk_iv, &ciphertext) {
            Ok(pt) => pt,
            Err(_) => return Err("Wrong password"),
        };

        writer.write_all(&plaintext).unwrap();

        print_progress_bar(
            reader.stream_position().unwrap() as f64 / file_size as f64, // We remove 16 bytes because we don't count the salt stored at the beginning of the file
            path,
        );
    }

    // Process remaining bytes, if any
    if remaining_bytes > 0 {
        let mut last_buf = vec![0u8; remaining_bytes as usize];
        reader.read_exact(&mut last_buf).unwrap();

        let chunk_iv: [u8; 16] = last_buf[..16].try_into().unwrap();
        let ciphertext = &last_buf[16..];

        let plaintext = match decrypt(key, chunk_iv, &ciphertext) {
            Ok(pt) => pt,
            Err(_) => return Err("Wrong password"),
        };

        writer.write_all(&plaintext).unwrap();
    }

    // Print a newline after the progress bar
    println!();

    if delete {
        match std::fs::remove_file(path) {
            Ok(_) => (),
            Err(_) => return Err("Failed to delete original file"),
        }
    }

    Ok(())
}

/// Generate a random IV using OsRng
fn gen_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    match OsRng.try_fill_bytes(&mut iv) {
        Ok(_) => iv,
        Err(_) => panic!("Failed to generate IV"),
    }
}

/// Generate a 32-byte key from a password string and a random salt using Argon2id
fn gen_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let key = argon2::hash_raw(password.as_bytes(), salt, &Config::rfc9106_low_mem())
        .expect("Key derivation failed");

    assert_eq!(key.len(), 32); // Ensure the key is 32 bytes long

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key); // Copies exactly 32 bytes into the array
    key_array
}
