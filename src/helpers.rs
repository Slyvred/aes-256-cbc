use rpassword::read_password;
use std::io::Write;

/// Get user password and return it as a String
pub fn get_password(placeholder: &str) -> String {
    print!("{}", placeholder);
    std::io::stdout().flush().expect("Failed to flush stdout");

    match read_password() {
        Ok(password) => password,
        Err(_) => {
            println!("Failed to read password");
            std::process::exit(1);
        }
    }
}

pub fn print_progress_bar(progress: f64, filename: &str) {
    let bar_width = 32;
    let pos = (bar_width as f64 * progress).round() as usize;
    let bar: String = (0..bar_width)
        .map(|i| if i < pos { '=' } else { ' ' })
        .collect();
    print!("\r[{}] {}", bar, filename);
    std::io::stdout().flush().unwrap();
}
