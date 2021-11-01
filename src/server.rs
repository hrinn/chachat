use std::net::TcpListener;
use std::net::TcpStream;
use std::io::prelude::*;
use std::error::Error;
use std::thread;

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
    let mut username_buffer = [0; 25];
    client.read(&mut username_buffer).unwrap();
    let username = String::from_utf8_lossy(&username_buffer);
    println!("{} connected", username);

    let mut buffer = [0; 1024];

    loop {
        client.read(&mut buffer).unwrap();
        println!("{}: {}", username, String::from_utf8_lossy(&buffer));
    }
}