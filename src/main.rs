extern crate clap;
use clap::{Arg, App, SubCommand, ArgMatches};
use std::process;
mod client;
mod server;

const DEFAULT_PORT: u16 = 3030;

fn main() {
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
                .index(3)))   
        .subcommand(SubCommand::with_name("server")
            .about("Launches the ChaChat server")
            .arg(Arg::with_name("port")
                .value_name("PORT")
                .help("Server's port")
                .index(1)))
            .get_matches();

    match app_m.subcommand() {
        ("client", Some(client_m)) => run_client(client_m),
        ("server", Some(server_m)) => run_server(server_m),
        _ => println!("No subcommand was used"),
    }
}

fn run_client(matches: &ArgMatches) {
    let username = matches.value_of("username").unwrap();
    let hostname = matches.value_of("hostname").unwrap();
    let port = parse_port(matches.value_of("port"));
    client::client(username, hostname, port).unwrap_or_else(|err| {
        println!("Unable to run client: {}", err);
        process::exit(1);
    });
}

fn run_server(matches: &ArgMatches) {
    let port = parse_port(matches.value_of("port"));
    server::server(port).unwrap_or_else(|err| {
        println!("Unable to run server: {}", err);
        process::exit(1);
    });
}

fn parse_port(port: Option<&str>) -> u16 {
    match port {
        Some(num) => num.parse().expect("Invalid port number"),
        _ => DEFAULT_PORT,
    }
}