use std::net::TcpListener;
use std::net::TcpStream;

pub fn server(port: u16) {
    let host = format!("localhost:{}", port);

    println!("Launching server on {}", host);

    let listener = TcpListener::bind(host).unwrap();

    for stream in listener.incoming() {
        let stream = stream.unwrap();

        handle_connection(stream);
    }
}

fn handle_connection(mut stream: TcpStream) {
    println!("New connection!");
}