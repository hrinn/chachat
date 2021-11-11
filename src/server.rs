use std::net::TcpListener;
use std::net::TcpStream;
use std::error::Error;
use std::thread;

use chachat::*;

pub fn server(port: u16) -> Result<(), Box<dyn Error>> {
    let host = format!("localhost:{}", port);

    println!("Launching server on {}", host);

    let listener = TcpListener::bind(host)?;

    // Iterate through new connections
    for client in listener.incoming() {
        let client = client.unwrap();

        // Add client to client table

        // Spawn a worker thread to handle this client
        thread::spawn(|| { 
            handle_client(client);
        });
    }

    Ok(())
}

fn handle_client(mut client: TcpStream) {
    // Read a handle PDU from the client
    let handle_pdu = HandlePDU::read_pdu(&mut client);

    // Get the handle from the PDU
    let username = handle_pdu.get_handle();
    println!("{} connected", username);

    loop {
        let buffer = match get_bytes_from_read(&mut client) {
            Ok(buf) => buf,
            Err(_) => {
                println!("{} disconnected", username);
                return;
            },
        };
        let message_pdu = MessagePDU::from_bytes(buffer);

        println!("{}->{}: {}", message_pdu.get_src_handle(), message_pdu.get_dest_handle(), message_pdu.get_message());
    }
}