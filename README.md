# port\_sniffer\_cli

A simple asynchronous TCP port scanner in Rust with a progress bar.
Scans a range of ports on a target IP concurrently using Tokio, prints progress and a final sorted list of open ports.

---

## Features

* Asynchronous TCP **connect** scanning using Tokio
* Configurable concurrency and start/end port range
* Progress bar (indicatif) with ETA
* Prints a sorted list of discovered open ports

---

## Requirements

* Rust toolchain (stable) — install via [https://rustup.rs/](https://rustup.rs/)
* Network access to the target host/ports
* Platforms supported by Tokio (Linux, macOS, Windows)

---

## Build

From the project root (where `Cargo.toml` is):

```bash
cargo build --release
```

The compiled binary will be at `target/release/port_sniffer_cli`.

---

## Usage

Full form:

```bash
./target/release/port_sniffer_cli --ip 192.168.0.1 --start_port 1 --end_port 1024 --concurrency 50
```

Short flags example:

```bash
./target/release/port_sniffer_cli --ip 8.8.8.8 -s 1 -e 1024 -c 30
```

### CLI options

* `--ip <IP>` (required)
  Target IPv4 or IPv6 address.

* `-c, --concurrency <N>` (optional, default: `50`)
  Number of concurrent scanning tasks. Valid range: `1`–`100`.

* `-s, --start_port <PORT>` (optional, default: `1`)
  First port in the scanning range.

* `-e, --end_port <PORT>` (optional, default: `65535`)
  Last port in the scanning range.

---

## Behavior notes

* Each connection attempt uses a **3 second** timeout.
* The scanner performs TCP `connect()` attempts only. It does **not** perform SYN/stealth or UDP scans.
* Open ports are collected via an internal `mpsc` channel and listed at the end of the run.
* The channel buffer size is set in code (`CHANNEL_BUFFER_SIZE`). For typical targets this is fine; scanning a host with hundreds or thousands of open ports could cause temporary backpressure during collection — the implementation is intentionally simple and pragmatic.

---

## Example output

**No open ports:**

```
[00:00:10] ======================================== 1024/1024 (0s)
Scan Completed Successfully!

No open ports found.
```

**Some open ports:**

```
[00:00:03] ======================================== 1024/1024 (0s)
Scan Completed Successfully!

Open ports:
22
80
443
8080
```

---

## Safety & Ethics

Only scan hosts and networks you own, administer, or have explicit permission to test. Unauthorized scanning may be treated as malicious activity and could be illegal in some jurisdictions.

---

## License

Add a `LICENSE` file to your repository to specify a license. This project does not include a license by default.

---

## Author

Sinameru

---

## Contributing / Improvements (optional)

Ideas you might add later — none require changing the core scanning logic:

* Graceful Ctrl+C handling to stop scanning early and print partial results
* Stream discovered ports to stdout as they arrive (instead of collecting all then printing)
* A test harness to reproduce edge-case behavior and stress-test channel/backpressure

---

This `README.md` documents the current behavior and usage without changing your scanner code. Keep scanning responsibly.
