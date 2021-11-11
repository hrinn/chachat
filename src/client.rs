use std::net::TcpStream;
use std::io;
use std::io::Write;
use std::error::Error;

use chachat::{HandlePDU, MessagePDU};

pub fn client(handle: &str, hostname: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let host = format!("{}:{}", hostname, port);
    println!("{} connecting to {}", handle, host);

    let mut server = TcpStream::connect(host)?;

    // Send handle to server
    let handle_pdu = HandlePDU::new(handle);
    server.write(handle_pdu.as_bytes())?;

    // Read user input, send it to server
    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut message = String::new();

        io::stdin()
            .read_line(&mut message)
            .expect("Failed to read user input");

        // Construct Message PDU
        let message_pdu = MessagePDU::new(handle, "aperlin", message.replace("\n", "").as_str());

        server.write(message_pdu.as_bytes())?;
    }
}