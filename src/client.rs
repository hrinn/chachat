use mio::net::TcpStream as MioTcpStream;
use std::net::TcpStream as StdTcpStream;
use std::io::{self, Write};
use std::error::Error;

use chachat::{HandlePDU, HandleRespPDU, MessagePDU};

pub fn client(handle: &str, hostname: &str, port: u16) -> Result<(), Box<dyn Error>> {
    // Connect to server
    let host = format!("{}:{}", hostname, port);
    println!("Connecting to {}", host);
    let server = StdTcpStream::connect(host)?;
    let mut server = MioTcpStream::from_stream(server)?;

    // Send handle to server
    let handle_pdu = HandlePDU::new(handle);
    server.write(handle_pdu.as_bytes())?;

    // Read server's response
    let handle_resp_bytes = read_stream(&server, )
    let handle_resp_pdu = HandleRespPDU::(&mut server);
    if !handle_resp_pdu.is_accept() {
        // Handle was rejected
        println!("Handle {} is already in use", handle);
        return Ok(());
    }

    // Handle was accepted
    println!("real smooth...");
    println!("Type /h for help");
    let usage = "COMMANDS:\n    /h - Help\n    /l - List users\n    /s - Start session\n    /m - Send message\n    /e - Exit";

    // Parse commands from user
    loop {
        print!("> ");
        io::stdout().flush().unwrap();

        let mut command = String::new();

        io::stdin()
            .read_line(&mut command)
            .expect("Failed to read user input");

        match &command[0..2] {
            "/m" | "/M" => send_message(handle, &command, &mut server),
            "/s" | "/S" => eprintln!("Not implemented."),
            "/l" | "/L" => eprintln!("Not implemented."),
            "/h" | "/H" => println!("{}", usage),
            "/e" | "/E" => return Ok(()),
            _ => eprintln!("Unknown command. Type /h for help"),
        }
    }
}

fn send_message(handle: &str, command: &str, mut server: &MioTcpStream) {
    let command = command[3..].replace("\n", "");
    let index = match command.find(' ') {
        Some(i) => i,
        None => {
            eprintln!("USAGE: /m <USER> <MESSAGE>");
            return;
        }
    };

    let (dest, message) = command.split_at(index);
    let message_pdu = MessagePDU::new(handle, dest, message);
    server.write(message_pdu.as_bytes()).unwrap();
}