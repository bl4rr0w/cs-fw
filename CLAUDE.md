# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CS-FW is a high-performance Counter-Strike 1.6 firewall built using Linux XDP (eXpress Data Path) and eBPF technology. It operates at the kernel level to provide DDoS protection specifically for CS 1.6 game servers.

## Architecture

This is a Rust project with two main components:
- **Main application** (`src/main.rs`): User-space application that loads and manages eBPF programs using Aya
- **eBPF probes** (`probes/`): Kernel-space packet filtering logic using XDP

### Key Components

- `src/main.rs`: Main CLI application that attaches XDP programs to network interfaces
- `probes/src/ddos_protection/main.rs`: Core XDP packet filtering logic written in eBPF
- `probes/src/lib.rs`: Library entry point for eBPF probes
- `xtask/`: Build system for compiling eBPF programs

## Build Process

The build process uses modern Aya framework with cargo-xtask:

1. **Build eBPF probes**:
   ```bash
   cargo xtask build-ebpf --release
   ```

2. **Build main application**:
   ```bash
   cargo xtask build --release
   ```

3. **Build both (recommended)**:
   ```bash
   cargo xtask build-ebpf --release && cargo xtask build --release
   ```

The eBPF probes must be compiled first because the main application includes the compiled eBPF bytecode at build time.

## Dependencies

- Requires Rust stable with nightly for eBPF compilation
- System packages: `libbpf-dev`
- Root privileges required for XDP attachment

## Development Requirements

**System**: Ubuntu 22.04 LTS, x86_64 architecture
**Privileges**: Must run as root for eBPF/XDP operations

## Key Libraries

- `aya`: Modern eBPF library for Rust (replaces redbpf)
- `aya-bpf`: eBPF-side library for kernel programs
- `network-types`: Network packet parsing
- `clap`: Command-line argument parsing
- `tokio`: Async runtime
- `log`: Logging

## Runtime Usage

The application requires two parameters:
- `-i, --interface`: Network interface to attach XDP program to
- `-p, --proxy`: Server address in IPv4:PORT format

Example: `sudo ./csfw -i eth0 -p 127.0.0.1:55555`

## XDP Attachment Strategy

The application tries multiple XDP modes in order of preference:
1. HwMode (hardware offload)
2. DrvMode (driver level)
3. SkbMode (socket buffer level)
4. Default mode

## Unloading

To detach the XDP program: `sudo ip link set dev <interface> xdp off`