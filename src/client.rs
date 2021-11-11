use std::net::TcpStream;
use std::io;
use std::io::Write;
use std::error::Error;

use chachat::HandlePDU;

pub fn client(handle: &str, hostname: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let host = format!("{}:{}", hostname, port);
    println!("{} connecting to {}", handle, host);

    let mut server = TcpStream::connect(host)?;

    // Send handle to server
    let handle_pdu = HandlePDU::from_handle(handle);
    server.write(handle_pdu.as_bytes())?;

    // Read user input, send it to server
    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut message = String::new();

        io::stdin()
            .read_line(&mut message)
            .expect("Failed to read user input");

        server.write(message.replace("\n", "").as_bytes())?;
    }
}