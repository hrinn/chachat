use std::error::Error;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::io::{self, BufReader, AsyncBufReadExt, AsyncWriteExt};
use chachat::*;

pub async fn client(handle: &str, hostname: &str, port: u16) -> Result<(), Box<dyn Error + 'static>> {
    // Connect to server
    let host = format!("{}:{}", hostname, port);
    println!("Connecting to {}", host);
    let server = TcpStream::connect(host).await?;

    // Send handle to server
    let handle_pdu = HandlePDU::new(handle);
    write_stream(&server, handle_pdu.as_bytes()).await;

    // Read server's response
    let handle_resp_bytes = read_pdu(&server).await?;
    let handle_resp_pdu = HandleRespPDU::from_bytes(handle_resp_bytes);
    if !handle_resp_pdu.is_accept() {
        // Handle was rejected
        println!("Handle {} is already in use", handle);
        return Ok(()); // TODO: Descriptive error
    }

    let write_server = Arc::new(server);
    let read_server = Arc::clone(&write_server);

    // Spawn a task for reading commands from user
    tokio::spawn(async move{
        handle_input_from_user(&handle_pdu.get_handle(), write_server).await;
    });

    // Spawn a task for reading messages from server
    tokio::spawn(async move {
        handle_pdus_from_server(read_server).await;
    });

    Ok(())
}

async fn handle_input_from_user(handle: &str, server: Arc<TcpStream>) {
    // Handle was accepted
    println!("Type /h for help");
    let usage = "COMMANDS:\n    /h - Help\n    /l - List users\n    \
    /s - Start session\n    /m - Send message\n    /e - Exit";

    let mut reader = BufReader::new(io::stdin());
    let mut buffer = String::new();
    
    // Parse commands from user
    loop {
        buffer.clear();
        print!("> "); // Probably need to flush stdout

        reader.read_line(&mut buffer).await.unwrap();

        match &buffer[0..2] {
            "/m" | "/M" => send_message(handle, &buffer, &server).await,
            "/s" | "/S" => eprintln!("Not implemented."),
            "/l" | "/L" => eprintln!("Not implemented."),
            "/h" | "/H" => println!("{}", usage),
            "/e" | "/E" => return,
            _ => eprintln!("Unknown command. Type /h for help"),
        }
    }
}

async fn handle_pdus_from_server(server: Arc<TcpStream>) {
    loop {
        let buf = read_pdu(&server).await.unwrap();

        match get_flag_from_bytes(&buf) {
            7 => display_message(MessagePDU::from_bytes(buf)).await,
            _ => eprintln!("Not implemented."),
        }
    }
}

async fn send_message(handle: &str, buffer: &str, server: &TcpStream) {
    let buffer = buffer[3..].replace("\n", "");
    let index = match buffer.find(' ') {
        Some(i) => i,
        None => {
            eprintln!("USAGE: /m <USER> <MESSAGE>");
            return;
        }
    };

    let (dest, message) = buffer.split_at(index);
    let message_pdu = MessagePDU::new(handle, dest, message);
    write_stream(server, message_pdu.as_bytes()).await;
}

async fn display_message(pdu: MessagePDU) {
    let out = format!("{}: {}", pdu.get_src_handle(), pdu.get_message());
    let mut stdout = io::stdout();
    stdout.write_all(out.as_bytes()).await.unwrap();
}