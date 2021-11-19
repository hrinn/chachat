use std::error::Error;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc::{Sender, Receiver, channel};
use tokio::io::{AsyncWriteExt};
use futures::lock::Mutex;
use chachat::*;

type SenderMap = Arc<Mutex<HashMap<String, Sender<Vec<u8>>>>>;

pub async fn server(port: u16) -> Result<(), Box<dyn Error>> {
    // Create a hashmap for associating handles with channels
    let channels = Arc::new(Mutex::new(HashMap::new()));

    // Set up TCP Listener
    let host = format!("localhost:{}", port);
    println!("Launching server on {}", host);
    let listener = TcpListener::bind(host).await?;

    loop {
        let (client, addr) = listener.accept().await?;

        let (mut read_client, mut write_client) = client.into_split();

        let channels = Arc::clone(&channels);
        let handle_bytes = read_pdu(&mut read_client).await?;
        let handle_pdu = HandlePDU::from_bytes(handle_bytes);

        if channels.lock().await.contains_key(&handle_pdu.get_handle()) {
            send_handle_response(&mut write_client, false).await;
            println!("{} connecting from {} rejected: Handle already in use", 
                handle_pdu.get_handle(), addr);
        } else {
            send_handle_response(&mut write_client, true).await;
            println!("{} connected from {}", handle_pdu.get_handle(), addr);
            // Create a channel for talking to this client
            let (tx, rx) = channel(32);

            // Add handle and channel to channels table
            channels.lock().await.insert(handle_pdu.get_handle(), tx);
 
            tokio::spawn(async move {
                handle_pdus_from_client(&mut read_client, &handle_pdu.get_handle(), channels).await;
            });

            tokio::spawn(async move {
                handle_pdus_to_client(&mut write_client, rx).await;
            });
        }       
    }
}

async fn send_handle_response(client: &mut OwnedWriteHalf, accepted: bool) {
    let flag: u8 = if accepted {
        2
    } else {
        3
    };
    let pdu = FlagOnlyPDU::new(flag);
    client.write_all(pdu.as_bytes()).await.unwrap_or_else(|e| {
        eprintln!("error sending handle response to client: {:?}", e);
    });
}

async fn handle_pdus_from_client(client: &mut OwnedReadHalf, handle: &String, channels: SenderMap) {
    loop {
        let buf = match read_pdu(client).await {
        Err(_) => {
            println!("{} disconnected", handle);
            // remove sender that corresponds to this handle from sender map
            channels.lock().await.remove(handle);
            return;
        },
        Ok(buf) => buf
        };

        match get_flag_from_bytes(&buf) {
            4 => handle_session_init(SessionInitPDU::from_bytes(buf), &channels).await,
            7 => handle_message(MessagePDU::from_bytes(buf), &channels).await,
            _ => unreachable!()
        }
    }
}

async fn handle_message(pdu: MessagePDU, channels: &SenderMap) {
    println!("{} -> {}: {}B", pdu.get_src_handle(), pdu.get_dest_handle(), pdu.get_ciphertext().len());
    forward_pdu(&pdu.get_dest_handle(), &pdu.get_src_handle(), pdu.as_vec(), channels).await;
}

async fn handle_session_init(pdu: SessionInitPDU, channels: &SenderMap) {
    println!("{} -> {}: Propose session", pdu.get_src_handle(), pdu.get_dest_handle());
    forward_pdu(&pdu.get_dest_handle(), &pdu.get_src_handle(), pdu.as_vec(), channels).await;
}

async fn forward_pdu(dest: &str, src: &str, pdu: Vec<u8>, channels: &SenderMap) {
    if let Some(tx) = channels.lock().await.get(dest) {
        tx.send(pdu).await.unwrap();
        return;
    }

    println!("User {} is not logged in", dest);
    let pdu = FlagOnlyPDU::new(8);
    if let Some(my_tx) = channels.lock().await.get(src) {
        my_tx.send(pdu.as_vec()).await.unwrap(); // Send no recipient PDU back to client
    } else {
        panic!("{} is not in session map", src);
    }
}

async fn handle_pdus_to_client(write_client: &mut OwnedWriteHalf, mut rx: Receiver<Vec<u8>> ) {
    loop {
        if let Some(msg) = rx.recv().await {
            write_client.write_all(&msg).await.unwrap();
        } else {
            return; // Channel closed, client disconnected
        }
    }
}