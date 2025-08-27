// Import necessary crates
use clap::{Arg, Command, value_parser}; // For CLI argument parsing
use std::net::IpAddr; // Represents an IP address
use std::sync::Arc; // For atomic reference-counted pointer (thread-safe shared ownership)
use tokio::net::TcpStream; // Async TCP connections using Tokio
use tokio::sync::mpsc; // Async multi-producer, single-consumer channel
use tokio::task::spawn; // Spawn asynchronous tasks
use indicatif::{ProgressBar, ProgressStyle}; // For progress bars in the terminal

/* -------------------------
   Constants
   ------------------------- */
// CLI metadata
const APP_NAME: &str = "port_sniffer_cli";
const VERSION: &str = "1.0";
const AUTHOR: &str = "Sinameru";
const ABOUT: &str = "Simple port scanner CLI";

// Command-line argument names and help strings
// IP
const LONG_IP: &str = "ip"; 
const HELP_IP: &str = "Target IP address";

// Threads
const LONG_THREADS: &str = "threads";
const SHORT_THREADS: char = 't';
const HELP_THREADS: &str = "Number of threads (1-100, default 4)";
const DEFAULT_THREADS: &str = "4";

// Start port
const LONG_START_PORT: &str = "start_port";
const SHORT_START_PORT: char = 's';
const DEFAULT_START_PORT: &str = "1";

// End port
const LONG_END_PORT: &str = "end_port";
const SHORT_END_PORT: char = 'e';
const DEFAULT_END_PORT: &str = "65535";

// Min/Max TCP ports
const MIN_PORT: u16 = 1; // Minimum valid TCP port
const MAX_PORT: u16 = 65535; // Maximum valid TCP port

/* -------------------------
   Async scan function
   ------------------------- */
/// `scan` attempts to connect to a given IP and port asynchronously.
/// If successful, it sends the port through an mpsc channel and increments the progress bar.
async fn scan(tx: mpsc::Sender<u16>, port: u16, addr: IpAddr, pb: Arc<ProgressBar>) {
    // Attempt TCP connection asynchronously
    if TcpStream::connect((addr, port)).await.is_ok() {
        // If successful, send the open port to the receiver
        let _ = tx.send(port).await;
    }
    // Update the progress bar regardless of success/failure
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
            Arg::new(LONG_THREADS)
                .short(SHORT_THREADS)
                .long(LONG_THREADS)
                .help(HELP_THREADS)
                .default_value(DEFAULT_THREADS)
                .value_parser(|x: &str| {
                    // Validate that the thread count is numeric and within 1–100
                    let val: usize = x.parse().map_err(|_| format!("`{x}` is not a number"))?;
                    if (1..=100).contains(&val) {
                        Ok(val)
                    } else {
                        Err(String::from("Threads must be between 1 and 100"))
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
    let _threads = matches.get_one::<usize>(LONG_THREADS).copied().expect("Default ensured by clap");
    let start_port = matches.get_one::<u16>(LONG_START_PORT).copied().expect("Default ensured by clap");
    let end_port = matches.get_one::<u16>(LONG_END_PORT).copied().expect("Default ensured by clap");

    // Simple sanity check: start port should not exceed end port
    if start_port > end_port {
        eprintln!("Error: start_port ({start_port}) cannot be greater than end_port ({end_port})");
        return;
    }

    // Compute total number of ports to scan
    let total_ports: u16 = end_port - start_port + 1;

    // Create a progress bar and wrap it in an Arc for shared ownership
    let pb = Arc::new({
        let pb = ProgressBar::new(total_ports as u64);
        let style = ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({eta})") // Visual layout
            .unwrap()
            .progress_chars("=>-"); // Characters for the progress bar
        pb.set_style(style);
        pb
    });

    // Create a channel to collect open ports
    let (tx, mut rx) = mpsc::channel(100);

    // Spawn an async task per port
    for port in start_port..=end_port {
        let tx = tx.clone(); // Clone sender for each task
        let pb = pb.clone(); // Clone Arc for shared progress bar
        spawn(async move { 
            scan(tx, port, ip, pb).await 
        });
    }

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
    for p in open_ports {
        println!("{p} is open");
    }
}
