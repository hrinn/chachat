use std::error::Error;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::net::*;
use tokio::sync::mpsc::{Sender, Receiver, channel};

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
        let (client, address) = listener.accept().await?;
        println!("incoming connection from {:?}", address);

        let channels = Arc::clone(&channels);
        let handle_bytes = read_pdu(&client).await?;
        let handle_pdu = HandlePDU::from_bytes(handle_bytes);

        if channels.lock().unwrap().contains_key(&handle_pdu.get_handle()) {
            send_handle_response(&client, false);
            println!("{} connecting from {} rejected: Handle already in use", 
                handle_pdu.get_handle(), client.peer_addr().unwrap());
        } else {
            send_handle_response(&client, true);
            println!("{} connected from {}", handle_pdu.get_handle(), client.peer_addr().unwrap());
            // Create a channel for talking to this client
            let (tx, rx) = channel(32);

            // Add handle and channel to channels table
            channels.lock().unwrap().insert(handle_pdu.get_handle(), tx);

            
            let write_client = Arc::new(client);
            let read_client = Arc::clone(&write_client);
            tokio::spawn(async move {
                handle_pdus_from_client(read_client, &handle_pdu.get_handle(), channels);
            });

            tokio::spawn(async move {
                handle_pdus_to_client(write_client, rx);
            });
        }       
    }
}

async fn send_handle_response(client: &TcpStream, accepted: bool) {
    let pdu = HandleRespPDU::new(accepted);
    write_stream(client, pdu.as_bytes()).await;
}

async fn handle_pdus_from_client(client: Arc<TcpStream>, handle: &String, channels: SenderMap) {
    loop {
        let buf = match read_pdu(&client).await {
        Err(e) => {
            println!("{:?}", e);
            // remove sender that corresponds to this handle from sender map 
            return;
        },
        Ok(buf) => buf
        };

        match get_flag_from_bytes(&buf) {
            7 => handle_message(MessagePDU::from_bytes(buf), &channels).await,
            _ => unreachable!()
        }
    }
}

async fn handle_message(pdu: MessagePDU, channels: &SenderMap) {
    let dest_handle = pdu.get_dest_handle();
    if let Some(tx) = channels.lock().unwrap().get(&dest_handle) {
        tx.send(pdu.as_vec()).await.unwrap();
    } else {
        println!("user {} is not logged in", dest_handle);
    }
}

async fn handle_pdus_to_client(client: Arc<TcpStream>, mut rx: Receiver<Vec<u8>> ) {
    loop {
        if let Some(msg) = rx.recv().await {
            write_stream(&client, &msg);
        } else {
            return;
        }
    }
}