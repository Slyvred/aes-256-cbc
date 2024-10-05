use std::env;
mod aes;
mod file;

use aes::{decrypt_dir, decrypt_file, encrypt_dir, encrypt_file, gen_key_from_password};

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

    let key = gen_key_from_password(password_str.as_str());

    match mode as &str {
        "--enc" => {
            if is_dir {
                // Encrypt all files in directory and subdirectories
                encrypt_dir(password_str.len(), key, &file);
            } else {
                encrypt_file(file.as_str(), password_str.len(), key);
            }
        }
        "--dec" => {
            if is_dir {
                // Decrypt all files in directory and subdirectories
                decrypt_dir(key, password_str.len(), &file);
            } else {
                decrypt_file(file.as_str(), password_str.len(), key);
            }
        }
        _ => {
            println!("Invalid mode");
        }
    }
}
