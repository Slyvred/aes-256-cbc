use std::io::{Read, Write};

/// Read a file into a vector of bytes
pub fn read_file(path: &str) -> Result<Vec<u8>, &str> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => {
            return Err("File not found");
        }
    };
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    Ok(buf)
}

/// Write a vector of bytes to a file
pub fn write_file<'a>(path: &'a str, data: &'a [u8]) -> Result<(), &'a str> {
    let mut file = match std::fs::File::create(path) {
        Ok(file) => file,
        Err(_) => {
            return Err("Failed to create file");
        }
    };

    if file.write_all(data).is_err() {
        return Err("Failed to write to file");
    }

    Ok(())
}

/// Get user input and return it as a String
pub fn get_input(placeholder: &str) -> String {
    print!("{}", placeholder);
    std::io::stdout().flush().expect("Failed to flush stdout");

    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    input.trim().to_string()
}
