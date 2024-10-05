use std::env;
mod aes;
mod file;

use aes::{append_iv, decrypt, decrypt_dir, encrypt, encrypt_dir, extract_iv, gen_iv};
use file::{read_file, write_file};

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
    let file = file.replace(['\"', '\''], "");

    // Check if file is directory
    let is_dir = std::fs::metadata(&file).unwrap().is_dir();

    let password_str = &args[5];
    let password_str = password_str.replace(['\"', '\''], "");

    let key = aes::gen_key_from_password(password_str.as_str());

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
