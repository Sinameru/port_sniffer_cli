//! # port_sniffer_cli
//!
//! A simple asynchronous TCP port scanner in Rust with a progress bar.
//! Scans a range of ports on a target IP concurrently using Tokio.
//!
//! ## Example Usage
//!
//! ```bash
//! port_sniffer_cli --ip 192.168.0.1 --start_port 1 --end_port 1024 --concurrency 50
//! ```

// Import required crates
use clap::{Arg, Command, value_parser}; // CLI argument parsing
use std::net::IpAddr; // Represents an IP address
use std::sync::Arc; // Atomic reference-counted pointer for thread-safe sharing
use tokio::net::TcpStream; // Asynchronous TCP connections using Tokio
use tokio::sync::mpsc; // Async multi-producer, single-consumer channel
use tokio::time::{timeout, Duration}; // Set timeouts for async operations
use futures::stream::StreamExt; // for `for_each_concurrent` on streams
use indicatif::{ProgressBar, ProgressStyle}; // Terminal progress bars

/* -------------------------
   Constants
   ------------------------- */

/// Application name
const APP_NAME: &str = "port_sniffer_cli";
/// Version
const VERSION: &str = "1.0";
/// Author
const AUTHOR: &str = "Sinameru";
/// About description
const ABOUT: &str = "Simple port scanner CLI";

/// Long name for IP argument
const LONG_IP: &str = "ip";
/// Help message for IP argument
const HELP_IP: &str = "Target IP address";

/// Long name for concurrency argument
const LONG_CONCURRENCY: &str = "concurrency";
/// Short name for concurrency argument
const SHORT_CONCURRENCY: char = 'c';
/// Help message for concurrency argument
const HELP_CONCURRENCY: &str = "Number of concurrent scans (1-100, default 50)";
/// Default concurrency value
const DEFAULT_CONCURRENCY: &str = "50";

/// Long name for start port
const LONG_START_PORT: &str = "start_port";
/// Short name for start port
const SHORT_START_PORT: char = 's';
/// Default start port
const DEFAULT_START_PORT: &str = "1";

/// Long name for end port
const LONG_END_PORT: &str = "end_port";
/// Short name for end port
const SHORT_END_PORT: char = 'e';
/// Default end port
const DEFAULT_END_PORT: &str = "65535";

/// Minimum valid TCP port
const MIN_PORT: u16 = 1;
/// Maximum valid TCP port
const MAX_PORT: u16 = 65535;

/// Buffer size for the mpsc channel
const CHANNEL_BUFFER_SIZE: usize = 250;

/* -------------------------
   Asynchronous scan function
   ------------------------- */

/// Attempts to connect to a given IP and port asynchronously.
/// 
/// If the connection succeeds, the port is sent through the mpsc channel and
/// the progress bar is incremented.
///
/// # Arguments
///
/// * `tx` - Channel sender to report open ports
/// * `port` - Port number to test
/// * `addr` - Target IP address
/// * `pb` - Shared progress bar
async fn scan(tx: mpsc::Sender<u16>, port: u16, addr: IpAddr, pb: Arc<ProgressBar>) {
    // Timeout of 3 seconds for the connection attempt
    let result = timeout(Duration::from_secs(3), TcpStream::connect((addr, port))).await;

    // Ok(Ok(_)) = connection succeeded before timeout
    if let Ok(Ok(_)) = result {
        // Send the open port to the channel (ignore failure)
        let _ = tx.send(port).await;
    }

    // Increment the progress bar regardless of success or failure
    pb.inc(1);
}

/* -------------------------
   Main function
   ------------------------- */

/// Main asynchronous entry point using Tokio runtime
#[tokio::main]
async fn main() {
    // Parse command-line arguments with clap
    let matches = Command::new(APP_NAME)
        .version(VERSION)
        .author(AUTHOR)
        .about(ABOUT)
        .arg(
            Arg::new(LONG_IP)
                .long(LONG_IP)
                .help(HELP_IP)
                .required(true) // IP is mandatory
                .value_parser(value_parser!(IpAddr)), // Auto-parse as IP
        )
        .arg(
            Arg::new(LONG_CONCURRENCY)
                .short(SHORT_CONCURRENCY)
                .long(LONG_CONCURRENCY)
                .help(HELP_CONCURRENCY)
                .default_value(DEFAULT_CONCURRENCY)
                .value_parser(|x: &str| {
                    // Validate number and range
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

    // Extract values from CLI arguments
    let ip = matches.get_one::<IpAddr>(LONG_IP).copied().expect("Required by clap");
    let concurrency = matches.get_one::<usize>(LONG_CONCURRENCY).copied().unwrap();
    let start_port = matches.get_one::<u16>(LONG_START_PORT).copied().expect("Default ensured by clap");
    let end_port = matches.get_one::<u16>(LONG_END_PORT).copied().expect("Default ensured by clap");

    // Ensure start_port <= end_port
    if start_port > end_port {
        eprintln!("Error: start_port ({start_port}) cannot be greater than end_port ({end_port})");
        std::process::exit(1);
    }

    // Total number of ports to scan
    let total_ports: u64 = (end_port - start_port + 1).into();

    // Create a shared progress bar
    let pb = Arc::new({
        let pb = ProgressBar::new(total_ports);
        let style = ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.red/cyan} {pos}/{len} ({eta})")
            .unwrap_or_else(|_| ProgressStyle::default_bar()) // fallback if template fails
            .progress_chars("=>-");
        pb.set_style(style);
        pb
    });

    // Create channel for collecting open ports
    let (tx, mut rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);

    // Create a stream of ports to scan
    let ports = tokio_stream::iter(start_port..=end_port);

    // Scan ports concurrently with the specified limit
    ports
        .for_each_concurrent(concurrency, |port| {
            let tx = tx.clone();
            let pb = pb.clone();
            async move {
                scan(tx, port, ip, pb).await;
            }
        })
        .await;

    drop(tx); // Close the channel when all tasks finish

    // Collect open ports from the channel
    let mut open_ports = vec![];
    while let Some(port) = rx.recv().await {
        open_ports.push(port);
    }

    // Finish the progress bar with a message
    pb.finish_with_message("Scan Completed Successfully!");

    println!();

    // Sort and display open ports
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
