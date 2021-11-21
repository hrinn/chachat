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
    let handle_pdu = HandlePDU::new(handle, 1);
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

    // Wait for tasks to end / kill them
    stdio_handler.await?;
    server_handler.abort();
    server_writer.await?;

    Ok(())
}

fn prompt() {
    std::io::stdout().write_all("> ".as_bytes()).unwrap();
    std::io::stdout().flush().unwrap();
}

async fn handle_input_from_user(handle: &str, tx: Sender<Vec<u8>>, sessions: SessionsMap, rsa_info: Arc<Mutex<RSAInfo>>, mut nonce_gen: ChaCha20Rng) -> Result<(), Box<dyn Error>> {
    // Handle was accepted
    println!("Type /h for help");
    let usage = "COMMANDS:\n    /h - Help\n    /u - List users\n    \
        /l - List sessions\n    /s - Start session\n    \
        /m - Send message\n    /e - Exit";

    // Parse commands from user
    loop {
        prompt();
        let input = stdin_readline().await;
        
        if input.len() < 2 {
            eprintln!("Unknown command. Type /h for help");
            continue;
        }

        match &input[0..2] {
            "/h" | "/H" => println!("{}", usage),
            "/u" | "/U" => list_users(&tx).await,
            "/l" | "/L" => list_sessions(&sessions).await,
            "/s" | "/S" => initiate_session(handle, &input, &tx, &sessions, &rsa_info).await,
            "/m" | "/M" => send_message(handle, &input, &tx, &sessions, &mut nonce_gen).await.unwrap(),
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

async fn list_users(tx: &Sender<Vec<u8>>) {
    let pdu = FlagOnlyPDU::new(10);
    tx.send(pdu.as_vec()).await.unwrap();
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

    // Determine if the session has been accepted
    if !sessions.lock().await.get(dest).unwrap().is_accepted() {
        eprintln!("{} has not accepted the session yet", dest);
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
    println!("> Sessions:");
    for (user, session_info) in &*(sessions.lock().await) {
        if session_info.is_accepted() {
            println!("    {}", user);
        }
    }
}

async fn handle_pdus_from_server(server: &mut OwnedReadHalf, tx: Sender<Vec<u8>>, sessions: SessionsMap, rsa_info: Arc<Mutex<RSAInfo>>) -> Result<(), Box<dyn Error>> {
    loop {
        let buf = match read_pdu(server).await {
            Ok(buf) => buf,
            Err(_) => return Ok(()), // Client disconnected, end this task
        };

        match get_flag_from_bytes(&buf) {
            4 => handle_session_init(&tx, SessionInitPDU::from_bytes(buf), &sessions, &rsa_info).await,
            5 => handle_session_accept(&tx, SessionAcceptPDU::from_bytes(buf), &sessions, &rsa_info).await,
            6 => handle_session_ack(SessionReplyPDU::from_bytes(buf), &sessions).await,
            7 => handle_session_rej(SessionReplyPDU::from_bytes(buf), &sessions).await,
            8 => display_message(MessagePDU::from_bytes(buf), &sessions).await,
            9 => handle_bad_dest(HandlePDU::from_bytes(buf), &sessions).await,
            11 => print_user_list(server).await,
            _ => eprintln!("Not implemented."),
        }

        prompt();
    }
}

async fn print_user_list(server: &mut OwnedReadHalf) {
    println!("Users:");

    loop {
        let buf = read_pdu(server).await.unwrap();

        match get_flag_from_bytes(&buf) {
            12 => {
                let pdu = HandlePDU::from_bytes(buf);
                println!("    {}", pdu.get_handle());
            },
            13 => return,
            _ => panic!("Bad PDU in user list"),
        }
    }
}

async fn handle_session_ack(pdu: SessionReplyPDU, sessions: &SessionsMap) {
    // Change status of session to accepted
    println!("Started session with {}", pdu.get_src_handle());
    sessions.lock().await.get_mut(&pdu.get_src_handle())
        .expect("Received session ACK from user not in session map!")
        .accept();
}

async fn handle_session_rej(pdu: SessionReplyPDU, sessions: &SessionsMap) {
    // Remove handle from session map
    println!("{} rejected session", pdu.get_src_handle());
    sessions.lock().await.remove(&pdu.get_src_handle());
}

async fn handle_session_init(tx: &Sender<Vec<u8>>, pdu: SessionInitPDU, sessions: &SessionsMap, rsa_info: &Arc<Mutex<RSAInfo>>) {
    // Check hash and signature
    if pdu.check_hash() && check_signature(&pdu.get_src_handle(), pdu.get_signature(), rsa_info).await {
        // Decrypt the session key
        let key = rsa_info.lock().await.decrypt(pdu.get_key());

        // Add key to session map
        let session = SessionInfo::from_key(&key);
        sessions.lock().await.insert(pdu.get_src_handle(), session);

        println!("{} requested to start a session", pdu.get_src_handle());
        send_session_accept(tx, &pdu.get_dest_handle(), &pdu.get_src_handle(), rsa_info).await;
    } else {
        // Could not be verified
        println!("Receive bad session init from {}", pdu.get_src_handle());
        // Send REJ
        send_sessions_reply(tx, &pdu.get_dest_handle(), &pdu.get_src_handle(), false).await;
    }

    
}

async fn send_sessions_reply(tx: &Sender<Vec<u8>>, handle: &str, dest: &str, ack: bool) {
    let pdu = SessionReplyPDU::new(handle, dest, ack);
    tx.send(pdu.as_vec()).await.unwrap();
}

async fn send_session_accept(tx: &Sender<Vec<u8>>, handle: &str, dest: &str, rsa_info: &Arc<Mutex<RSAInfo>>) {
    // Sign your own handle
    let signature = rsa_info.lock().await.sign(handle.as_bytes());

    // Send PDU
    let pdu = SessionAcceptPDU::new(handle, dest, &signature);
    tx.send(pdu.as_vec()).await.unwrap();
}

async fn handle_session_accept(tx: &Sender<Vec<u8>>, pdu: SessionAcceptPDU, sessions: &SessionsMap, rsa_info: &Arc<Mutex<RSAInfo>>) {
    // Check hash and signature
    if pdu.check_hash() && check_signature(&pdu.get_src_handle(), pdu.get_signature(), rsa_info).await {
        println!("Started session with {}", pdu.get_src_handle());
        // Change status of session info to accepted
        sessions.lock().await.get_mut(&pdu.get_src_handle()).unwrap().accept();
        // Send ACK
        send_sessions_reply(tx, &pdu.get_dest_handle(), &pdu.get_src_handle(), true).await;
    } else {
        println!("Could not start session with {}. Received bad reply", pdu.get_src_handle());
        // Remove sender from session map
        sessions.lock().await.remove(&pdu.get_src_handle());
        // Send REJ
        send_sessions_reply(tx, &pdu.get_dest_handle(), &pdu.get_src_handle(), false).await;
    }
}

async fn check_signature(handle: &str, signature: &[u8], rsa_info: &Arc<Mutex<RSAInfo>>) -> bool {
    // Get path to the sender's public key
    let key_path = get_public_key_path(handle);
    let key_str = key_path_to_str(&key_path).unwrap();

    // Verify the signature on the pdu
    rsa_info.lock().await.verify(signature, handle, &key_str).unwrap_or_else(|_| {
        println!("Unable to accept session from {}. You do not have their public key", handle);
        false
    })
}

async fn display_message(pdu: MessagePDU, sessions: &SessionsMap) {
    let nonce = Nonce::from_slice(pdu.get_nonce());

    match sessions.lock().await.get(&pdu.get_src_handle())
        .expect("Received a message from a user you do not have a session with!")
        .get_cipher().decrypt(nonce, pdu.get_ciphertext().as_ref()) {
        Ok(plaintext) => {
            let message = String::from_utf8_lossy(&plaintext);
            println!("{}: {}", pdu.get_src_handle(), message)
        },
        Err(_) => {
            println!("Message from {} was modified in transit!", pdu.get_src_handle())
        },
    };
}

async fn handle_bad_dest(pdu: HandlePDU, sessions: &SessionsMap) {
    println!("{} is not logged in", pdu.get_handle());

    // Remove bad dest from session map
    sessions.lock().await.remove(&pdu.get_handle());
}

async fn write_to_server(server: &mut OwnedWriteHalf, mut rx: Receiver<Vec<u8>>) {
    loop {
        if let Some(pdu) = rx.recv().await {
            server.write_all(&pdu).await.unwrap();
        } else {
            return; // Channel closed,
        }
    }
}

fn generate_nonce(nonce_gen: &mut ChaCha20Rng) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    nonce_gen.fill(&mut nonce);
    nonce.to_vec()
}