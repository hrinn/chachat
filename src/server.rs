use std::net::TcpListener;
use std::net::TcpStream;
use std::io::prelude::*;
use std::error::Error;
use std::thread;

use chachat::HandlePDU;

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

    let mut buffer = [0; 1024];

    loop {
        buffer.fill(0);
        match client.read(&mut buffer) {
            Ok(0) => {
                println!("{} disconnected", username);
                return;
            },
            Err(e) => panic!("Failed to read from client TcpStream: {}", e),
            Ok(_) => (),
        }
        println!("{}: {}", username, String::from_utf8_lossy(&buffer));
    }
}