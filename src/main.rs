extern crate clap;
use clap::{App, Arg, ArgMatches, SubCommand};
use std::process;
mod client;
mod keygen;
mod server;

const DEFAULT_PORT: u16 = 3030;

#[tokio::main]
async fn main() {
    let app_m = App::new("ChaChat")
        .version("0.1.0")
        .author("Hayden Rinn and Adam Perlin")
        .about("An encrypted messaging program for the command line")
        .subcommand(
            SubCommand::with_name("client")
                .about("Launches the ChaChat client")
                .arg(
                    Arg::with_name("handle")
                        .value_name("HANDLE")
                        .help("Handle to receive and send messages from")
                        .required(true)
                        .index(1),
                )
                .arg(
                    Arg::with_name("hostname")
                        .value_name("HOST")
                        .help("Server's hostname")
                        .required(true)
                        .index(2),
                )
                .arg(
                    Arg::with_name("port")
                        .value_name("PORT")
                        .help("Server's port")
                        .index(3),
                ),
        )
        .subcommand(
            SubCommand::with_name("server")
                .about("Launches the ChaChat server")
                .arg(
                    Arg::with_name("port")
                        .value_name("PORT")
                        .help("Server's port")
                        .index(1),
                ),
        )
        .subcommand(
            SubCommand::with_name("keygen")
                .about("Generates an RSA key to be used with ChaChat")
                .arg(
                    Arg::with_name("handle")
                        .value_name("HANDLE")
                        .help("Handle for logging into the server")
                        .required(true)
                        .index(1),
                ),
        )
        .get_matches();

    match app_m.subcommand() {
        ("client", Some(client_m)) => run_client(client_m).await,
        ("server", Some(server_m)) => run_server(server_m).await,
        ("keygen", Some(keygen_m)) => run_keygen(keygen_m),
        _ => println!("No subcommand was used"),
    }
}

async fn run_client(matches: &ArgMatches<'_>) {
    let handle = matches.value_of("handle").unwrap();
    let hostname = matches.value_of("hostname").unwrap();
    let port = parse_port(matches.value_of("port"));

    if let Err(e) = client::client(handle, hostname, port).await {
        println!("Client encountered error: {}", e);
        process::exit(1);
    }
}

async fn run_server(matches: &ArgMatches<'_>) {
    let port = parse_port(matches.value_of("port"));

    if let Err(e) = server::server(port).await {
        println!("Server encountered error: {}", e);
        process::exit(1);
    }
}

fn parse_port(port: Option<&str>) -> u16 {
    match port {
        Some(num) => num.parse().expect("Invalid port number"),
        _ => DEFAULT_PORT,
    }
}

fn run_keygen(matches: &ArgMatches<'_>) {
    let handle = matches.value_of("handle").unwrap();

    if let Err(e) = keygen::keygen(handle) {
        println!("Error generating key: {}", e);
        process::exit(1);
    }
}
