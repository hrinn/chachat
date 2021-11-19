use std::error::Error;
use std::io::Write;
use std::sync::Arc;
use std::collections::HashMap;
use futures::lock::Mutex;
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedWriteHalf, OwnedReadHalf};
use tokio::sync::mpsc::{Sender, Receiver, channel};
use tokio::io::AsyncWriteExt;
use chacha20poly1305::Nonce;
use chacha20poly1305::aead::Aead;
use rand_chacha::ChaCha20Rng;
use rand::Rng;
use rand::SeedableRng;
use chachat::*;

type SessionsMap = Arc<Mutex<HashMap<String, SessionInfo>>>;

pub async fn client(handle: &str, hostname: &str, port: u16) -> Result<(), Box<dyn Error + 'static>> {
    // Connect to server
    let host = format!("{}:{}", hostname, port);
    println!("Connecting to {}", host);
    let server = TcpStream::connect(host).await?;

    // Break the server into a read half and write half
    let (mut read_server, mut write_server) = server.into_split();

    // Send handle to server
    let handle_pdu = HandlePDU::new(handle);
    write_server.write_all(handle_pdu.as_bytes()).await?;

    // Read server's response
    let handle_resp_bytes = read_pdu(&mut read_server).await?;
    if get_flag_from_bytes(&handle_resp_bytes) == 3 {
        // Handle was rejected
        println!("Handle {} is already in use", handle);
        return Ok(()); // TODO: Descriptive error
    }

    // Create channels for thread communication
    let (tx, rx) = channel(32);
    let tx_clone = tx.clone();

    // Create RSA Info (holds everything for RSA encryption)
    let key_path = get_private_key_path(handle);
    let key_str = key_path_to_str(&key_path)?;
    let rsa_info = Arc::new(Mutex::new(RSAInfo::new(&key_str)));
    let rsa_info_clone = Arc::clone(&rsa_info);

    // Setup SessionInfo Map (holds everything for ChaCha encryption per session)
    let sessions: SessionsMap = Arc::new(Mutex::new(HashMap::new()));
    let sessions_clone = Arc::clone(&sessions);

    // Setup Nonce generator
    let nonce_gen = ChaCha20Rng::from_entropy();

    // Spawn a task for reading commands from user
    let stdio_handler = tokio::spawn(async move {
        handle_input_from_user(&handle_pdu.get_handle(), tx, sessions, rsa_info, nonce_gen).await.unwrap_or_else(|e| {
            eprintln!("error in user input task: {}", e)
        })
    });

    // Spawn a task for reading messages from server
    let server_handler = tokio::spawn(async move {
        handle_pdus_from_server(&mut read_server, tx_clone, sessions_clone, rsa_info_clone).await.unwrap_or_else(|e| {
            eprintln!("error in message reader task: {}", e);
        })
    });

    // Spawn a task for writing messages to server
    let server_writer = tokio::spawn(async move {
        write_to_server(&mut write_server, rx).await;
    });

    tokio::try_join!(stdio_handler, server_handler, server_writer)?;

    Ok(())
}

async fn write_to_server(server: &mut OwnedWriteHalf, mut rx: Receiver<Vec<u8>>) {
    loop {
        if let Some(pdu) = rx.recv().await {
            println!("Writing {}B to server", pdu.len());
            server.write_all(&pdu).await.unwrap();
        } else {
            return; // Channel closed,
        }
    }
}

async fn handle_input_from_user(handle: &str, tx: Sender<Vec<u8>>, sessions: SessionsMap, rsa_info: Arc<Mutex<RSAInfo>>, mut nonce_gen: ChaCha20Rng) -> Result<(), Box<dyn Error>> {
    // Handle was accepted
    println!("Type /h for help");
    let usage = "COMMANDS:\n    /h - Help\n    /u - List users\n    \
        /l - List sessions\n    /s - Start session\n    \
        /m - Send message\n    /e - Exit";

    // Parse commands from user
    loop {
        std::io::stdout().write_all("> ".as_bytes())?;
        std::io::stdout().flush()?;
        let input = stdin_readline().await;
        
        if input.len() < 2 {
            eprintln!("Unknown command. Type /h for help");
            continue;
        }

        match &input[0..2] {
            "/m" | "/M" => send_message(handle, &input, &tx, &sessions, &mut nonce_gen).await.unwrap(),
            "/s" | "/S" => initiate_session(handle, &input, &tx, &sessions, &rsa_info).await,
            "/l" | "/L" => list_sessions(&sessions).await,
            "/u" | "/U" => eprintln!("Not implemented."),
            "/h" | "/H" => println!("{}", usage),
            "/e" | "/E" => return Ok(()),
            _ => eprintln!("Unknown command. Type /h for help"),
        }
    }
}

async fn stdin_readline() -> String {
    tokio::task::spawn_blocking(|| {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        return input.trim().to_string();
    }).await.expect("Failed to read line from stdin")
}

async fn send_message(handle: &str, input: &str, tx: &Sender<Vec<u8>>, sessions: &SessionsMap, nonce_gen: &mut ChaCha20Rng) -> Result<(), Box<dyn Error>> {
    let message_usage = "USAGE: /m <USER> <MESSAGE>";
    if input.len() < 3 {
        eprintln!("{}", message_usage);
        return Ok(())
    }
    let input = &input[3..];
    let index = match input.find(' ') {
        Some(i) => i,
        None => {
            eprintln!("{}", message_usage);
            return Ok(())
        }
    };

    let (dest, message) = input.split_at(index);

    // Determine if there is a session with the dest user
    if !sessions.lock().await.contains_key(dest) {
        eprintln!("You do not have an active session with {}. Use /s", dest);
        return Ok(())
    }

    let nonce = generate_nonce(nonce_gen);
    let ciphertext = sessions.lock().await.get(dest).unwrap()
        .get_cipher()
        .encrypt(Nonce::from_slice(&nonce), message[1..].as_ref())
        .expect("Failed to encrypt message!");
    
    let message_pdu = MessagePDU::new(handle, dest, nonce.as_slice(), &ciphertext);

    tx.send(message_pdu.as_vec()).await?;

    Ok(())
}

async fn initiate_session(handle: &str, input: &str, tx: &Sender<Vec<u8>>, sessions: &SessionsMap, rsa_info: &Arc<Mutex<RSAInfo>>) {
    // Parse user input
    let session_usage = "USAGE: /s <USER>";
    if input.len() < 3 {
        eprintln!("{}", session_usage);
        return;
    }

    let dest = &input[3..];
    
    if sessions.lock().await.contains_key(dest) {
        println!("Session already active with {}", dest);
        return;
    }

    // Generate a session key and store it in map
    let key = rsa_info.lock().await.generate_session_key();
    sessions.lock().await.insert(dest.to_string(), SessionInfo::from_key(&key));

    // Encrypt session key with dest's public key
    let key_path = get_public_key_path(dest);
    let key_str = key_path_to_str(&key_path).expect("Invalid path to public key");
    let encrypted_key = rsa_info.lock().await.encrypt(&key, &key_str);

    // Sign handle with your private key
    let signature = rsa_info.lock().await.sign(handle.as_bytes());

    // Send packet
    let pdu = SessionInitPDU::new(handle, dest, &signature, &encrypted_key);
    tx.send(pdu.as_vec()).await.unwrap();
}

async fn list_sessions(sessions: &SessionsMap) {
    println!("Active sessions:");
    for user in sessions.lock().await.keys() {
        println!("    {}", user);
    }
}

async fn handle_pdus_from_server(server: &mut OwnedReadHalf, tx: Sender<Vec<u8>>, sessions: SessionsMap, rsa_info: Arc<Mutex<RSAInfo>>) -> Result<(), Box<dyn Error>> {
    loop {
        let buf = match read_pdu(server).await {
            Ok(buf) => buf,
            Err(_) => return Ok(()), // Client disconnected, end this task
        };

        match get_flag_from_bytes(&buf) {
            4 => accept_session(&tx, SessionInitPDU::from_bytes(buf), &sessions, &rsa_info).await,
            7 => display_message(MessagePDU::from_bytes(buf), &sessions).await?,
            8 => println!("User is not logged in.\n> "), // Remove them from the sessions if one is active
            _ => eprintln!("Not implemented."),
        }
    }
}

async fn accept_session(tx: &Sender<Vec<u8>>, pdu: SessionInitPDU, sessions: &SessionsMap, rsa_info: &Arc<Mutex<RSAInfo>>) {
    // Check hash on pdu
    if !pdu.check_hash() {
        println!("Computed hash did not match sent hash. Message may have changed in transit.");
        return;
    }
    
    // Get path to the sender's public key
    let key_path = get_public_key_path(&pdu.get_src_handle());
    let key_str = key_path_to_str(&key_path).unwrap();

    // Verify the signature on the pdu
    let result = rsa_info.lock().await.verify(pdu.get_signature(), &pdu.get_src_handle(), &key_str).unwrap_or_else(|_| {
        println!("Unable to accept session from {}. You do not have their public key", pdu.get_src_handle());
        false
    });

    if !result {
        println!("{}'s signature could not be verified", pdu.get_src_handle());
        return;
    }

    // Decrypt the session key
    let key = rsa_info.lock().await.decrypt(pdu.get_key());

    // Add key to session map
    let session = SessionInfo::from_key(&key);
    sessions.lock().await.insert(pdu.get_src_handle(), session);

    println!("Accepted new session from {}", pdu.get_src_handle());

    send_session_accept(tx, &pdu.get_dest_handle(), &pdu.get_src_handle(), rsa_info).await;
}

async fn send_session_accept(tx: &Sender<Vec<u8>>, handle: &str, dest: &str, rsa_info: &Arc<Mutex<RSAInfo>>) {
    // Sign your own handle
    let signature = rsa_info.lock().await.sign(handle.as_bytes());

    // Send PDU
    let pdu = SessionReplyPDU::new(handle, dest, &signature);
    tx.send(pdu.as_vec()).await.unwrap();
}

async fn display_message(pdu: MessagePDU, sessions: &SessionsMap) -> Result<(), tokio::task::JoinError> {
    let nonce = Nonce::from_slice(pdu.get_nonce());

    let out = match sessions.lock().await.get(&pdu.get_src_handle())
        .expect("Received a message from a user you do not have a session with!")
        .get_cipher().decrypt(nonce, pdu.get_ciphertext().as_ref()) {
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

fn generate_nonce(nonce_gen: &mut ChaCha20Rng) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    nonce_gen.fill(&mut nonce);
    nonce.to_vec()
}