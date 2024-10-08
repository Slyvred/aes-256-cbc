use std::env;
mod aes;
mod helpers;

use aes::{decrypt_file, encrypt_file};
use helpers::get_password;

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

    // Check if file exists and isn't a directory
    let path = std::path::Path::new(&file);

    if !path.exists() {
        println!("File not found");
        return;
    } else if path.is_dir() {
        println!("Path is a directory, not a file");
        return;
    }

    let password_str = get_password("Enter password: ");

    match mode as &str {
        "--enc" => {
            let confirm_password = get_password("Confirm password: ");

            if password_str != confirm_password {
                println!("Passwords do not match !");
                return;
            }

            encrypt_file(&file, &password_str);
        }
        "--dec" => {
            decrypt_file(&file, &password_str);
        }
        _ => {
            println!("Invalid mode");
        }
    }
}
