# CS-FW: Counter-Strike 1.6 Firewall

A high-performance DDoS protection firewall specifically designed for Counter-Strike 1.6 game servers, built using Linux XDP (eXpress Data Path) and eBPF technology.

## Features

- **Kernel-level packet filtering** using XDP for maximum performance
- **Steam protocol awareness** with A2S query handling
- **UDP amplification attack protection** blocking common reflection sources
- **Two-stage connection validation** system
- **Whitelist/blacklist management** with LRU caching
- **Multiple XDP attachment modes** (Hardware → Driver → Socket Buffer → Generic)

## Architecture

CS-FW operates at the Linux kernel level using eBPF programs attached via XDP, providing:

- **Zero-copy packet processing** for minimal latency
- **Early packet dropping** before network stack processing
- **Stateful connection tracking** for legitimate clients
- **Protocol-specific filtering** for CS 1.6 traffic patterns

## Requirements

- **Linux kernel 4.18+** with XDP support
- **Ubuntu 22.04 LTS** (recommended)
- **Root privileges** for eBPF program loading
- **Rust toolchain** (stable + nightly for development)

## Installation

### Pre-built Binary

Download the latest binary from the [Releases](https://github.com/bl4rr0w/cs-fw/releases) page.

### Build from Source

```bash
# Install dependencies
sudo apt update
sudo apt install -y libbpf-dev

# Install Rust toolchains
rustup toolchain install stable nightly
rustup component add rust-src --toolchain nightly

# Install bpf-linker
cargo install bpf-linker

# Clone and build
git clone https://github.com/bl4rr0w/cs-fw.git
cd cs-fw

# Build eBPF programs
cargo xtask build-ebpf --release

# Build main application
cargo xtask build --release

# Binary will be at target/release/csfw
```

## Usage

```bash
sudo ./csfw -i <interface> -p <server_ip:port>
```

### Options

- `-i, --interface <INTERFACE>` - Network interface to attach XDP program to (e.g., `eth0`)
- `-p, --proxy <PROXY>` - Server address in IPv4:PORT format (e.g., `192.168.1.100:27015`)

### Example

```bash
# Protect CS 1.6 server running on 192.168.1.100:27015 via eth0 interface
sudo ./csfw -i eth0 -p 192.168.1.100:27015
```

## How It Works

### Packet Processing Pipeline

1. **Interface Check** - Packets arrive at XDP hook on specified interface
2. **Protocol Filtering** - Only IPv4 UDP packets are processed
3. **Bypass Check** - Hardcoded bypass IPs are always allowed
4. **Server Validation** - Packets to/from configured servers are handled
5. **Amplification Protection** - Common UDP reflection ports are blocked
6. **Steam Protocol Analysis** - A2S queries and responses are validated
7. **Whitelist Check** - Known good IPs bypass further filtering
8. **Two-Stage Validation** - Unknown clients must complete handshake

### Protection Mechanisms

- **UDP Amplification Blocking**: Drops packets from DNS, NTP, memcached, etc.
- **A2S Response Filtering**: Blocks spoofed server responses
- **Connection State Tracking**: Maintains temporary and permanent whitelists
- **Rate Limiting**: LRU maps automatically expire old entries

## Unloading

To detach the XDP program:

```bash
sudo ip link set dev <interface> xdp off
```

## Development

### Project Structure

```
cs-fw/
├── src/                    # Main application (userspace)
├── probes/                 # eBPF programs (kernel space)
├── xtask/                  # Build system
└── .github/workflows/      # CI/CD
```

### Build System

The project uses `cargo-xtask` for building:

```bash
# Build eBPF programs only
cargo xtask build-ebpf [--release]

# Build userspace application only
cargo xtask build [--release]

# Build everything
cargo xtask build-ebpf --release && cargo xtask build --release
```

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Disclaimer

This software is provided as-is for educational and defensive purposes only. Users are responsible for complying with all applicable laws and regulations when deploying network security tools.
