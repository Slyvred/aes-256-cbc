use std::io::{Read, Write};

/// Read a file into a vector of bytes
pub fn read_file(path: &str) -> Vec<u8> {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => {
            println!("File not found");
            return Vec::new();
        }
    };
    let mut buf = Vec::new();
    file.read_to_end(&mut buf).unwrap();
    buf
}

/// Write a vector of bytes to a file
pub fn write_file(path: &str, data: &[u8]) {
    let mut file = match std::fs::File::create(path) {
        Ok(file) => file,
        Err(_) => {
            println!("Failed to create file");
            return;
        }
    };

    file.write_all(data).unwrap();
    println!("{}", path);
}
