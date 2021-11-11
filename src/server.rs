use std::net::TcpListener;
use std::net::TcpStream;
use std::error::Error;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::io::Write;
use bytes::BytesMut;

use chachat::*;

pub fn server(port: u16) -> Result<(), Box<dyn Error>> {
    // Create a hashmap for associating handles with channels
    let channels = Arc::new(Mutex::new(HashMap::new()));

    // Set up TCP Listener
    let host = format!("localhost:{}", port);
    println!("Launching server on {}", host);
    let listener = TcpListener::bind(host)?;

    // Iterate through new connections
    for client in listener.incoming() {
        let mut client = client.unwrap();
        let channels = Arc::clone(&channels);
        
        // Get the handle from the client
        let handle_pdu = HandlePDU::read_pdu(&mut client);

        // Check to see if the handle is already in the table
        if channels.lock().unwrap().contains_key(&handle_pdu.get_handle()) {
            send_handle_response(&client, false);
            println!("{} connecting from {} rejected: Handle already in use", 
                handle_pdu.get_handle(), client.peer_addr().unwrap());
        } else {
            send_handle_response(&client, true);
            println!("{} connected from {}", handle_pdu.get_handle(), client.peer_addr().unwrap());
            // Create a channel for talking to this client
            let (sender, receiver) = mpsc::channel();

            // Add handle and channel to channels table
            channels.lock().unwrap().insert(handle_pdu.get_handle(), sender);

            // Spawn a thread to handle this client
            thread::spawn(move || {
                handle_client(client, channels, receiver);
            });
        }       
    }

    Ok(())
}

fn send_handle_response(mut client: &TcpStream, accepted: bool) {
    let pdu = HandleRespPDU::new(accepted);
    client.write(pdu.as_bytes()).unwrap();
}

fn handle_client(mut client: TcpStream, channels: Arc<Mutex<HashMap<String, mpsc::Sender<BytesMut>>>>, receiver: mpsc::Receiver<BytesMut>) {
    // Wait for message packets
    loop {
        let buffer = match get_bytes_from_read(&mut client) {
            Ok(buf) => buf,
            Err(_) => {
                println!("Someone disconnected");
                return;
            },
        };
        let message_pdu = MessagePDU::from_bytes(buffer);

        println!("{}->{}: {}B", message_pdu.get_src_handle(), message_pdu.get_dest_handle(), message_pdu.get_message().len());
    }
}