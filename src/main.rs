use std::env;
mod aes;
mod helpers;

use aes::{decrypt_dir, decrypt_file, encrypt_dir, encrypt_file, gen_key_from_password};

fn main() {
    // Get password from command line arguments
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        println!("Usage: ./aes-cbc --<mode> <path>");
        println!("Modes: enc, dec");
        return;
    }

    // Usage: ./aes-cbc --<mode> <path>
    // Modes: enc, dec
    let mode = &args[1];
    let file = &args[2];

    // Sanitize file path
    let file = file.replace(['\"', '\''], "");

    // Check if file exists
    if !std::path::Path::new(&file).exists() {
        println!("File not found");
        return;
    }

    // Check if file is directory
    let is_dir = std::fs::metadata(&file).unwrap().is_dir();

    let password_str = helpers::get_input("Enter password: ");

    let key = gen_key_from_password(password_str.as_str());

    match mode as &str {
        "--enc" => {
            let confirm_password = helpers::get_input("Confirm password: ");

            if password_str != confirm_password {
                println!("Passwords do not match !");
                return;
            }

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
