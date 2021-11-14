use std::error::Error;
use std::io::Write;
use std::sync::Arc;
use futures::lock::Mutex;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use chacha20poly1305::{ChaCha20Poly1305 as ChaCha20, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use chachat::*;

type AMCipher = Arc<Mutex<ChaCha20>>;

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

    // Hard Coded Session Key
    let key = Key::from_slice(b"Hayden Rinn Adam Perlin ChaChat!"); // 32B
    let encrypt_cipher = Arc::new(Mutex::new(ChaCha20::new(key)));
    let decrypt_cipher = Arc::clone(&encrypt_cipher);

    // Spawn a task for reading commands from user
    let input_task = tokio::spawn(async move {
        handle_input_from_user(&handle_pdu.get_handle(), &mut write_server, encrypt_cipher).await.unwrap_or_else(|e| {
            eprintln!("error in user input task: {}", e)
        })
    });

    // Spawn a task for reading messages from server
    let read_task = tokio::spawn(async move {
        handle_pdus_from_server(&mut read_server, decrypt_cipher).await.unwrap_or_else(|e| {
            eprintln!("error in message reader task: {}", e);
        })
    });

    tokio::try_join!(input_task, read_task)?;

    Ok(())
}

async fn handle_input_from_user(handle: &str, server: &mut OwnedWriteHalf, cipher: AMCipher) -> Result<(), Box<dyn Error>> {
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
            "/m" | "/M" => send_message(handle, &input, server, &cipher).await.unwrap(),
            "/s" | "/S" => eprintln!("Not implemented."),
            "/l" | "/L" => eprintln!("Not implemented."),
            "/h" | "/H" => println!("{}", usage),
            "/e" | "/E" => return Ok(()),
            _ => eprintln!("Unknown command. Type /h for help"),
        }
    }
}

async fn handle_pdus_from_server(server: &mut OwnedReadHalf, cipher: AMCipher) -> Result<(), Box<dyn Error>> {
    loop {
        let buf = match read_pdu(server).await {
            Ok(buf) => buf,
            Err(_) => return Ok(()), // Client disconnected, end this task
        };

        match get_flag_from_bytes(&buf) {
            7 => display_message(MessagePDU::from_bytes(buf), &cipher).await?,
            _ => eprintln!("Not implemented."),
        }
    }
}

async fn send_message(handle: &str, buffer: &str, server: &mut OwnedWriteHalf, cipher: &AMCipher) -> Result<(), Box<dyn Error>> {
    let message_usage = "USAGE: /m <USER> <MESSAGE>";
    if buffer.len() < 3 {
        eprintln!("{}", message_usage);
        return Ok(())
    }
    let buffer = &buffer[3..];
    let index = match buffer.find(' ') {
        Some(i) => i,
        None => {
            eprintln!("{}", message_usage);
            return Ok(())
        }
    };

    let (dest, message) = buffer.split_at(index);
    
    let nonce = Nonce::from_slice(b"temp nonce!!");
    let ciphertext = cipher.lock().await.encrypt(nonce, message[1..].as_ref())
        .expect("Failed to encrypt user input!");
    
    let message_pdu = MessagePDU::new(handle, dest, nonce.as_slice(), &ciphertext);
    server.write_all( message_pdu.as_bytes()).await?;

    Ok(())
}

async fn display_message(pdu: MessagePDU, cipher: &AMCipher) -> Result<(), tokio::task::JoinError> {
    let nonce = Nonce::from_slice(pdu.get_nonce());
    // check if nonce

    let out = match cipher.lock().await.decrypt(nonce, pdu.get_ciphertext().as_ref()) {
        Ok(plaintext) => {
            let message = String::from_utf8_lossy(&plaintext);
            format!("{}: {}\n> ", pdu.get_src_handle(), message)
        },
        Err(_) => {
            format!("Message from {} was modified in transit!", pdu.get_src_handle())
        },
    };

    let mut stdout = std::io::stdout();
    tokio::task::spawn_blocking(move || {
        stdout.write(out.as_bytes()).unwrap();
        stdout.flush().unwrap();
    }).await
}