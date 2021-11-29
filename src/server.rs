use chachat::*;
use futures::lock::Mutex;
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpListener;
use tokio::sync::mpsc::{channel, Receiver, Sender};

type SenderMap = Arc<Mutex<HashMap<String, Sender<Vec<u8>>>>>;

pub async fn server(port: u16) -> Result<(), Box<dyn Error>> {
    // Create a hashmap for associating handles with channels
    let channels = Arc::new(Mutex::new(HashMap::new()));

    // Set up TCP Listener
    let host = format!("0.0.0.0:{}", port);
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
            println!(
                "{} connecting from {} rejected: Handle already in use",
                handle_pdu.get_handle(),
                addr
            );
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
    let flag: u8 = if accepted { 2 } else { 3 };
    let pdu = FlagOnlyPDU::new(flag);
    client.write_all(pdu.as_bytes()).await.unwrap_or_else(|e| {
        eprintln!("error sending handle response to client: {:?}", e);
    });
}

async fn handle_pdus_from_client(client: &mut OwnedReadHalf, handle: &str, channels: SenderMap) {
    loop {
        let buf = match read_pdu(client).await {
            Err(_) => {
                println!("{} disconnected", handle);
                // remove sender that corresponds to this handle from sender map
                channels.lock().await.remove(handle);
                return;
            }
            Ok(buf) => buf,
        };

        match get_flag_from_bytes(&buf) {
            4 | 5 | 6 | 7 | 8 => forward_pdu(ForwardPDU::from_bytes(buf), &channels).await,
            10 => send_user_list(handle, &channels).await,
            _ => unreachable!(),
        }
    }
}

async fn forward_pdu(pdu: ForwardPDU, channels: &SenderMap) {
    println!(
        "{} -> {}: {}B",
        pdu.get_src_handle(),
        pdu.get_dest_handle(),
        pdu.len()
    );

    if let Some(tx) = channels.lock().await.get(&pdu.get_dest_handle()) {
        tx.send(pdu.as_vec()).await.unwrap();
        return;
    }

    println!("{} is not logged in", pdu.get_dest_handle());

    let resp_pdu = HandlePDU::new(&pdu.get_dest_handle(), 9);
    if let Some(my_tx) = channels.lock().await.get(&pdu.get_src_handle()) {
        my_tx.send(resp_pdu.as_vec()).await.unwrap(); // Send no recipient PDU back to client
    } else {
        eprintln!("{} is not in session map", pdu.get_src_handle());
    }
}

async fn send_user_list(dest: &str, channels: &SenderMap) {
    let lock = channels.lock().await; // Hold the lock for the duration of this function

    // Get the channel to send back to the user
    let tx = lock.get(dest).expect("Send not in sender map");

    // Send start of list packet
    let start_pdu = FlagOnlyPDU::new(11);
    tx.send(start_pdu.as_vec()).await.unwrap();

    // Send each user
    for user in lock.keys() {
        if user != dest {
            let entry_pdu = HandlePDU::new(user, 12);
            tx.send(entry_pdu.as_vec()).await.unwrap();
        }
    }

    // Send end of list packet
    let end_pdu = FlagOnlyPDU::new(13);
    tx.send(end_pdu.as_vec()).await.unwrap();
}

async fn handle_pdus_to_client(write_client: &mut OwnedWriteHalf, mut rx: Receiver<Vec<u8>>) {
    loop {
        if let Some(msg) = rx.recv().await {
            write_client.write_all(&msg).await.unwrap();
        } else {
            return; // Channel closed, client disconnected
        }
    }
}
