use std::net::TcpStream;
use std::io;
use std::io::Write;
use std::error::Error;

pub fn client(username: &str, hostname: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let host = format!("{}:{}", hostname, port);
    println!("{} connecting to {}", username, host);

    let mut server = TcpStream::connect(host)?;

    // Send username
    server.write(username.as_bytes())?;

    // Read user input, send it to server
    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut message = String::new();

        io::stdin()
            .read_line(&mut message)
            .expect("Failed to user input");

        server.write(message.as_bytes())?;
    }
}