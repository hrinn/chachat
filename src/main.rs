extern crate clap;
use clap::{Arg, App, SubCommand, ArgMatches};
use std::process;
use std::env;
mod client;
mod server;
mod keygen;
use chachat::expand_tilde;

const DEFAULT_PORT: u16 = 3030;

#[tokio::main]
async fn main() {
    let app_m = App::new("ChaChat")
        .version("0.1.0")
        .author("Hayden Rinn and Adam Perlin")
        .about("An encrypted messaging program for the command line")
        .subcommand(SubCommand::with_name("client")
            .about("Launches the ChaChat client")
            .arg(Arg::with_name("username")
                .value_name("NAME")
                .help("Username to receive messages for and send messages from")
                .required(true)
                .index(1))
            .arg(Arg::with_name("hostname")
                .value_name("HOST")
                .help("Server's hostname")
                .required(true)
                .index(2))
            .arg(Arg::with_name("port")
                .value_name("PORT")
                .help("Server's port")
                .index(3))
            .arg(Arg::with_name("key_path")
                .value_name("KEY_PATH")
                .help("Path to your private key")
                .index(4)))   
        .subcommand(SubCommand::with_name("server")
            .about("Launches the ChaChat server")
            .arg(Arg::with_name("port")
                .value_name("PORT")
                .help("Server's port")
                .index(1)))
        .subcommand(SubCommand::with_name("keygen")
            .about("Generates an RSA key to be used with ChaChat"))
            .get_matches();

    match app_m.subcommand() {
        ("client", Some(client_m)) => run_client(client_m).await,
        ("server", Some(server_m)) => run_server(server_m).await,
        ("keygen", _) => run_keygen(),
        _ => println!("No subcommand was used"),
    }
}

async fn run_client(matches: &ArgMatches<'_>) {
    let username = matches.value_of("username").unwrap();
    let hostname = matches.value_of("hostname").unwrap();
    let port = parse_port(matches.value_of("port"));
    let default_key_path = format!("{}/.chachat/id_rsa", env::var("HOME").unwrap());
    let key_path = match matches.value_of("key_path") {
        Some(key_path) => expand_tilde(key_path),
        _ => default_key_path,
    };
    client::client(username, hostname, port, &key_path).await.unwrap_or_else(|err| {
        println!("Client encountered error: {}", err);
        process::exit(1);
    });
}

async fn run_server(matches: &ArgMatches<'_>) {
    let port = parse_port(matches.value_of("port"));
    server::server(port).await.unwrap_or_else(|err| {
        println!("Server encountered error: {}", err);
        process::exit(1);
    });
}

fn parse_port(port: Option<&str>) -> u16 {
    match port {
        Some(num) => num.parse().expect("Invalid port number"),
        _ => DEFAULT_PORT,
    }
}

fn run_keygen() {
    keygen::keygen().unwrap_or_else(|err| {
        println!("Error generating key: {}", err);
        process::exit(1);
    });
}