# CS-FW: Counter-Strike 1.6 Firewall

High-performance DDoS protection firewall for Counter-Strike 1.6 game servers using Linux XDP and eBPF.

## Features

- **Kernel-level packet filtering** with XDP for maximum performance
- **Steam protocol awareness** with A2S query handling
- **UDP amplification protection** blocking DNS, NTP, memcached, etc.
- **Two-stage validation** system for legitimate clients
- **Multiple XDP modes** (Hardware → Driver → Socket Buffer → Generic)

## Quick Start

```bash
# Download from releases or build from source
sudo ./csfw -i eth0 -p 192.168.1.100:27015
```

## Build from Source

```bash
# Install dependencies
sudo apt install -y libbpf-dev
cargo install bpf-linker
rustup component add rust-src --toolchain nightly

# Build
cargo xtask build-ebpf --release
cargo xtask build --release
```

## Usage

- `-i, --interface` - Network interface (e.g., `eth0`)
- `-p, --proxy` - Server address (e.g., `192.168.1.100:27015`)

**Unload:** `sudo ip link set dev <interface> xdp off`

## Credits

This is a modernized version of the original CS-FW project by [@hyperxpro](https://github.com/hyperxpro/cs-fw).

**Changes in this fork:**
- Migrated from legacy redbpf to modern aya eBPF framework
- Updated build system with cargo-xtask
- Fixed compatibility with current Rust toolchain
- All original DDoS protection logic preserved

## License

GNU General Public License v3.0
