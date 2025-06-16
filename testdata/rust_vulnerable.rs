use std::fmt;

// Define a User struct
struct User {
    first_name: String,
    last_name: String,
    email: String,
}

impl User {
    // Constructor to initialize properties
    fn new(first_name: &str, last_name: &str, email: &str) -> User {
        User {
            first_name: first_name.to_string(),
            last_name: last_name.to_string(),
            email: email.to_string(),
        }
    }
}

fn main() {
    // Create user object and assign strings
    let mut user = User::new("John", "Doe", "john@email.com");
    
    user.first_name = String::from("Bob");
    // Access string properties
    println!("{}", user.first_name);
    println!("{}", user.last_name);
    println!("{}", user.email);

    // Directly assigning string literals
    let ip: &str = "8.8.8.8";
    let pass: &str = "s3cr3tp@ssw0rd 2";
    // ...

    // Using escaped characters
    let api_key: &str = "Hello \"World\"";

    // Multiline string literal
    let multiline: &str = "This is a \nmultiline string literal";
    
    let key_id: &str = "AKIA6ODU5DHT7VPXGCE4";
    let aws_secret: &str = "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";
    let hidden_passphrase: &str = "blink182";

    // String interpolation (formatted print)
    let name: &str = "John";
    println!("Hello {}!", name);

    // String concatenation using the format! macro
    let first_name: &str = "John ";
    let last_name: &str = "Doe";
    let full_name: String = format!("{}{}", first_name, last_name);

    // Formatted string using format!
    let score: String = format!("The score is {}", 42);
}
