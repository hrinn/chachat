use std::error::Error;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use std::io::Write;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use chachat::*;

pub async fn client(handle: &str, hostname: &str, port: u16) -> Result<(), Box<dyn Error + 'static>> {
    // Connect to server
    let host = format!("{}:{}", hostname, port);
    println!("Connecting to {}", host);
    let server = TcpStream::connect(host).await?;

    let (mut read_server, mut write_server) = server.into_split();

    // Send handle to server
    let handle_pdu = HandlePDU::new(handle);
    write_server.write_all(handle_pdu.as_bytes()).await?;

    // Read server's response
    let handle_resp_bytes = read_pdu(&mut read_server).await?;
    let handle_resp_pdu = HandleRespPDU::from_bytes(handle_resp_bytes);
    if !handle_resp_pdu.is_accept() {
        // Handle was rejected
        println!("Handle {} is already in use", handle);
        return Ok(()); // TODO: Descriptive error
    } 


    // Spawn a task for reading commands from user
    let input_task = tokio::spawn(async move {
        handle_input_from_user(&handle_pdu.get_handle(), &mut write_server).await.unwrap_or_else(|e| {
            eprintln!("error in user input task: {}", e)
        })
    });

    // Spawn a task for reading messages from server
    let read_task = tokio::spawn(async move {
        handle_pdus_from_server(&mut read_server).await.unwrap_or_else(|e| {
            eprintln!("error in message reader task: {}", e);
        })
    });

    tokio::try_join!(input_task, read_task)?;

    Ok(())
}

async fn handle_input_from_user(handle: &str, server: &mut OwnedWriteHalf) -> Result<(), Box<dyn Error>> {
    // Handle was accepted
    println!("Type /h for help");
    let usage = "COMMANDS:\n    /h - Help\n    /l - List users\n    \
    /s - Start session\n    /m - Send message\n    /e - Exit";
    // Parse commands from user
    loop {
        std::io::stdout().write_all("> ".as_bytes())?;
        std::io::stdout().flush()?;
        let input = tokio::task::spawn_blocking(|| {
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            return input.trim().to_string();
        }).await.unwrap();
        
        if input.len() < 2 {
            continue;
        }
        // split input into vectors of str slices

        match &input[0..2] {
            "/m" | "/M" => send_message(handle, &input, server).await.unwrap(),
            "/s" | "/S" => eprintln!("Not implemented."),
            "/l" | "/L" => eprintln!("Not implemented."),
            "/h" | "/H" => println!("{}", usage),
            "/e" | "/E" => return Ok(()),
            _ => eprintln!("Unknown command. Type /h for help"),
        }
    }
}

async fn handle_pdus_from_server(server: &mut OwnedReadHalf) -> Result<(), Box<dyn Error>> {
    loop {
        let buf = match read_pdu(server).await {
            Ok(buf) => buf,
            Err(_) => return Ok(()), // Client disconnected, end this task
        };

        match get_flag_from_bytes(&buf) {
            7 => display_message(MessagePDU::from_bytes(buf)).await?,
            _ => eprintln!("Not implemented."),
        }
    }
}

async fn send_message(handle: &str, buffer: &str, server: &mut OwnedWriteHalf) -> Result<(), Box<dyn Error>> {
    if buffer.len() < 6 {
        eprintln!("USAGE: /m <USER> <MESSAGE>");
        return Ok(())
    }
    let buffer = &buffer[3..];
    let index = match buffer.find(' ') {
        Some(i) => i,
        None => {
            eprintln!("USAGE: /m <USER> <MESSAGE>");
            return Ok(())
        }
    };

    let (dest, message) = buffer.split_at(index);
    let message = &message[1..];
    let message_pdu = MessagePDU::new(handle, dest, message);
    server.write_all( message_pdu.as_bytes()).await?;

    Ok(())
}

async fn display_message(pdu: MessagePDU) -> Result<(), tokio::task::JoinError> {
    let out = format!("[{}]: {}\n> ", pdu.get_src_handle(), pdu.get_message());
    let mut stdout = std::io::stdout();
    tokio::task::spawn_blocking(move || {
        stdout.write(out.as_bytes()).unwrap();
        stdout.flush().unwrap();
    }).await
}