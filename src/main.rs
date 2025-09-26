//
// Copyright (C) 2023, Aayush Atharva
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//

use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use clap::Parser;
use log::{info, warn};
use std::net::SocketAddrV4;
use tokio::signal;

use probes::ddos_protection::SAddrV4;

/// Attach eBPF probes to deal with DDOS
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name of the interface to attach to
    #[arg(short, long)]
    interface: String,

    /// The address of the proxy in format IPv4:PORT
    #[arg(short, long)]
    proxy: SocketAddrV4,
}

// Pod implementation moved to probes crate

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();

    if unsafe { libc::geteuid() != 0 } {
        log::error!("You must be root to use eBPF!");
        std::process::exit(1);
    }

    // This will include your eBPF program compiled to bytecode at build time
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../target/bpfel-unknown-none/release/ddos_protection"
    ))?;

    // eBPF logger removed due to version conflicts

    let proxy = SAddrV4 {
        addr: u32::from_ne_bytes(args.proxy.ip().octets()).to_le(),
        port: (args.proxy.port() as u32).to_le(),
    };

    // Map the Server Address to the map
    let mut serverlist: HashMap<_, SAddrV4, u8> = HashMap::try_from(bpf.map_mut("SERVERLIST").unwrap())?;
    serverlist.insert(proxy, 0u8, 0)?;

    let program: &mut Xdp = bpf.program_mut("filter").unwrap().try_into()?;
    program.load()?;

    // Try different XDP modes in order of preference
    let xdp_modes = [
        XdpFlags::HW_MODE,
        XdpFlags::DRV_MODE,
        XdpFlags::SKB_MODE,
        XdpFlags::default(),
    ];

    let mut attached = false;
    for xdp_mode in xdp_modes {
        info!("Trying to attach XDP program on interface: {} with mode {:?}", args.interface, xdp_mode);

        match program.attach(&args.interface, xdp_mode) {
            Ok(_link_id) => {
                info!("Successfully attached XDP program on interface: {} with mode {:?}", args.interface, xdp_mode);
                attached = true;
                break;
            }
            Err(e) => {
                warn!("Failed to attach XDP program on interface: {} with mode {:?}, error: {}", args.interface, xdp_mode, e);
            }
        }
    }

    if !attached {
        return Err("Failed to attach XDP program with any mode".into());
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

// SPDX-License-Identifier: GPL-3.0
