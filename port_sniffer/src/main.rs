use clap::{Arg, Command};
use std::net::IpAddr;

fn main() {
    let matches = Command::new("port_sniffer")
        .version("1.0")
        .author("Sinameru")
        .about("Simple port scanner CLI")
        .arg(
            Arg::new("threads")
                .short('j')
                .long("threads")
                .value_name("THREADS")
                .help("Number of threads (1-100, default 4)")
                .default_value("4")
                .value_parser(clap::value_parser!(u16).range(1..=100)),
        )
        .arg(
            Arg::new("ip")
                .help("Target IP address")
                .required(true)
                .value_parser(clap::value_parser!(IpAddr)),
        )
        .get_matches();

    let threads = *matches.get_one::<u16>("threads").expect("Default ensured by clap");
    let ip = matches.get_one::<IpAddr>("ip").expect("Required by clap");

    println!("Parsed arguments: IP={} threads={}", ip, threads);
}