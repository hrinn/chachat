use std::error::Error;
use std::net::TcpListener;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::io::Write;

use bytes::BytesMut;

use mio::{Events, Poll, Token, Ready, PollOpt};
use mio::net::TcpStream;
use mio_extras::channel::{channel, Sender, Receiver};

use chachat::*;

type SenderMap = Arc<Mutex<HashMap<String, Sender<Vec<u8>>>>>;

pub fn server(port: u16) -> Result<(), Box<dyn Error>> {
    // Create a hashmap for associating handles with channels
    let channels = Arc::new(Mutex::new(HashMap::new()));

    // Set up TCP Listener
    let host = format!("localhost:{}", port);
    println!("Launching server on {}", host);
    let listener = TcpListener::bind(host)?;

    // Iterate through new connections
    for client in listener.incoming() {
        let mut client = TcpStream::from_stream(client.unwrap()).unwrap();
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
            let (sender, receiver) = channel();

            // Add handle and channel to channels table
            channels.lock().unwrap().insert(handle_pdu.get_handle(), sender);

            // Spawn a thread to handle this client
            thread::spawn(move || {
                handle_client(client, &handle_pdu.get_handle(), channels, receiver);
            });
        }       
    }

    Ok(())
}

fn send_handle_response(mut client: &TcpStream, accepted: bool) {
    let pdu = HandleRespPDU::new(accepted);
    client.write(pdu.as_bytes()).unwrap();
}

fn handle_client(client: TcpStream, handle: &String, channels: SenderMap, receiver: Receiver<Vec<u8>>) {
    // Setup polling
    let poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(128);

    // Register event sources (TcpStreams and Channels)
    const PDUS: Token = Token(0);
    poll.register(&client, PDUS, Ready::readable(), PollOpt::edge()).unwrap();
    poll.register(&receiver, PDUS, Ready::readable(), PollOpt::edge()).unwrap();

    // Wait for message packets
    loop {
        // Wait for packets from socket, or on messages on receiver
        poll.poll(&mut events, None).unwrap();

        for event in events.iter() {
            println!("{:?}", event);
        }

        // // Read PDU into bytes buffer
        // let buffer = match get_bytes_from_read(&mut client) {
        //     Ok(buf) => buf,
        //     Err(_) => {
        //         println!("{} disconnected", handle); /* TODO: pass clients username to thread */
        //         return;
        //     },
        // };

        // // Determine flag of PDU
        // match get_flag_from_bytes(&buffer) {
        //     7 => handle_message(buffer, &channels),
        //     _ => eprintln!("Received bad PDU from {}", handle),
        // }
    }
}

fn handle_message(buffer: BytesMut, channels: &SenderMap) {
    let message_pdu = MessagePDU::from_bytes(buffer);
    println!("{}->{}: {}B", message_pdu.get_src_handle(), message_pdu.get_dest_handle(), message_pdu.get_message().len());

    // Check if the dest handle is in the table
    if let Some(sender) = channels.lock().unwrap().get(&message_pdu.get_dest_handle()) {
        // Receipient is currently connected
        // Forward pdu to receiving client through channels
        // I should do a trait on the pdus that get sent to other users so that I can send it without changing
        sender.send(message_pdu.as_vec()).unwrap();
    } else {
        // Trying to send a message to someone who doesn't exist
        // TODO: Should we send an error back to the sender?
        eprintln!("{} is trying to message someone who doesn't exist!", message_pdu.get_src_handle());
    }
}