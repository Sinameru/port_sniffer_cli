// Import necessary crates
use clap::{Arg, Command, value_parser}; // For CLI argument parsing
use std::net::IpAddr; // Represents an IP address
use std::sync::Arc; // For atomic reference-counted pointer (thread-safe shared ownership)
use tokio::net::TcpStream; // Async TCP connections using Tokio
use tokio::sync::mpsc; // Async multi-producer, single-consumer channel
use tokio::time::{timeout, Duration}; // For setting timeouts on async operations
use futures::stream::StreamExt; // for for_each_concurrent
use indicatif::{ProgressBar, ProgressStyle}; // For progress bars in the terminal

/* -------------------------
   Constants
   ------------------------- */
// CLI metadata
const APP_NAME: &str = "port_sniffer_cli";
const VERSION: &str = "1.0";
const AUTHOR: &str = "Sinameru";
const ABOUT: &str = "Simple port scanner CLI";

// IP
const LONG_IP: &str = "ip"; 
const HELP_IP: &str = "Target IP address";

// Concurrency
const LONG_CONCURRENCY: &str = "concurrency";
const SHORT_CONCURRENCY: char = 'c';
const HELP_CONCURRENCY: &str = "Number of concurrent scans (1-100, default 50)";
const DEFAULT_CONCURRENCY: &str = "50";

// Start port
const LONG_START_PORT: &str = "start_port";
const SHORT_START_PORT: char = 's';
const DEFAULT_START_PORT: &str = "1";

// End port
const LONG_END_PORT: &str = "end_port";
const SHORT_END_PORT: char = 'e';
const DEFAULT_END_PORT: &str = "65535";

// Min/Max TCP ports
const MIN_PORT: u16 = 1;
const MAX_PORT: u16 = 65535;

// Buffer size for mpsc channel
const CHANNEL_BUFFER_SIZE: usize = 100;

/* -------------------------
   Async scan function
   ------------------------- */
/// `scan` attempts to connect to a given IP and port asynchronously.
/// If successful, it sends the port through an mpsc channel and increments the progress bar.
async fn scan(tx: mpsc::Sender<u16>, port: u16, addr: IpAddr, pb: Arc<ProgressBar>) {
    let result = timeout(Duration::from_secs(3), TcpStream::connect((addr, port))).await;
    // Ok(Ok(_)) means the connection succeeded before the timeout
    if let Ok(Ok(_)) = result {
        // Timeout did NOT fire, and connect succeeded
        let _ = tx.send(port).await;
    }
    // Otherwise: either timeout elapsed OR connect failed
    pb.inc(1);
}

/* -------------------------
   Main function
   ------------------------- */
#[tokio::main] // Marks this async main function for Tokio runtime
async fn main() {
    // Parse command-line arguments using clap
    let matches = Command::new(APP_NAME)
        .version(VERSION)
        .author(AUTHOR)
        .about(ABOUT)
        .arg(
            Arg::new(LONG_IP)
                .help(HELP_IP)
                .required(true) // IP is mandatory
                .value_parser(value_parser!(IpAddr)), // Automatically parses IP addresses
        )
        .arg(
            Arg::new(LONG_CONCURRENCY)
                .short(SHORT_CONCURRENCY)
                .long(LONG_CONCURRENCY)
                .help(HELP_CONCURRENCY)
                .default_value(DEFAULT_CONCURRENCY)
                .value_parser(|x: &str| {
                    let val: usize = x.parse().map_err(|_| format!("`{x}` is not a number"))?;
                    if (1..=100).contains(&val) {
                        Ok(val)
                    } else {
                        Err(String::from("Concurrency must be between 1 and 100"))
                    }
                }),
        )
        .arg(
            Arg::new(LONG_START_PORT)
                .short(SHORT_START_PORT)
                .long(LONG_START_PORT)
                .default_value(DEFAULT_START_PORT)
                .value_parser(|x: &str| {
                    // Validate start port
                    let val: u16 = x.parse().map_err(|_| format!("`{x}` is not a valid port"))?;
                    if val < MIN_PORT || val > MAX_PORT {
                        Err(format!("Port must be between {MIN_PORT} and {MAX_PORT}"))
                    } else {
                        Ok(val)
                    }
                }),
        )
        .arg(
            Arg::new(LONG_END_PORT)
                .short(SHORT_END_PORT)
                .long(LONG_END_PORT)
                .default_value(DEFAULT_END_PORT)
                .value_parser(|x: &str| {
                    // Validate end port
                    let val: u16 = x.parse().map_err(|_| format!("`{x}` is not a valid port"))?;
                    if val < MIN_PORT || val > MAX_PORT {
                        Err(format!("Port must be between {MIN_PORT} and {MAX_PORT}"))
                    } else {
                        Ok(val)
                    }
                }),
        )
        .get_matches();

    // Extract values from the parsed arguments
    let ip = matches.get_one::<IpAddr>(LONG_IP).copied().expect("Required by clap");
    let concurrency = matches.get_one::<usize>(LONG_CONCURRENCY).copied().unwrap();
    let start_port = matches.get_one::<u16>(LONG_START_PORT).copied().expect("Default ensured by clap");
    let end_port = matches.get_one::<u16>(LONG_END_PORT).copied().expect("Default ensured by clap");

    // Simple sanity check: start port should not exceed end port
    if start_port > end_port {
        eprintln!("Error: start_port ({start_port}) cannot be greater than end_port ({end_port})");
        std::process::exit(1);
    }

    // Compute total number of ports to scan
    let total_ports: u64 = (end_port - start_port + 1).into();

    // Create a progress bar and wrap it in an Arc for shared ownership
    let pb = Arc::new({
        let pb = ProgressBar::new(total_ports);
        let style = ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.red/cyan} {pos}/{len} ({eta})")
            .unwrap_or_else(|_| ProgressStyle::default_bar()) // fallback in case of error
            .progress_chars("=>-");
        pb.set_style(style);
        pb
    });

    // Create a channel to collect open ports
    let (tx, mut rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);

    // Iterate over the port range as a stream
    let ports = tokio_stream::iter(start_port..=end_port);

    ports
        .for_each_concurrent(concurrency, |port| {
            let tx = tx.clone();
            let pb = pb.clone();
            async move {
                scan(tx, port, ip, pb).await;
            }
        })
        .await;

    drop(tx); // Drop the original sender to close the channel when all tasks finish

    // Collect open ports from the channel
    let mut open_ports = vec![];
    while let Some(port) = rx.recv().await {
        open_ports.push(port);
    }

    // Finish the progress bar with a message
    pb.finish_with_message("Scan Completed Successfully!");

    println!();

    // Sort the ports and display them
    open_ports.sort();
    if open_ports.is_empty() {
        println!("No open ports found.");
    } else {
        println!("Open ports: ");
        for p in open_ports {
            println!("{p}");
        }
    }
}