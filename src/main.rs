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

use std::io::BufRead;
use clap::Parser;
use redbpf::{load::Loader, xdp, HashMap};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::str::FromStr;

/// Attach eBPF probes to deal with DDOS
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Name of the interface to attach to
    #[clap(short, long)]
    interface: String,

    /// The address of the proxy in format IPv4:PORT
    #[clap(short, long)]
    proxy: SocketAddrV4,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct SAddrV4 {
    pub addr: u32,
    pub port: u32,
}

// Define a struct to hold the CIDR address and mask
#[derive(Clone, Copy)]
#[repr(C, packed)]
struct Cidr {
    addr: u32,
    mask: u32,
}

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/ddos_protection/ddos_protection.elf"
    ))
}

fn main() -> Result<(), String> {
    let subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let args = Args::parse();

    if unsafe { libc::geteuid() != 0 } {
        tracing::error!("You must be root to use eBPF!");
        std::process::exit(1);
    }

    let xdp_mode = xdp::Flags::DrvMode;

    let mut loaded = Loader::load(probe_code()).map_err(|err| {
        dbg!(&err);
        format!("{:?}", err)
    })?;

    // Map the CIDR addresses into CIDR map
    let cidr_map = HashMap::<u32, u8>::new(loaded.map("CIDR")
        .expect("CIDR map not found"))
        .unwrap();

    // Netmask map
    let netmask_map = HashMap::<u32, u8>::new(loaded.map("NETMASK")
        .expect("NETMASK map not found"))
        .unwrap();

    // Read CIDR from file
    let file = std::fs::File::open("/root/cidr.txt").unwrap();
    let cidrs: Vec<Cidr> = std::io::BufReader::new(file)
        .lines()
        .filter_map(|line| {
            line.ok().and_then(|l| {
                let parts: Vec<&str> = l.splitn(2, '/').collect();
                let addr = Ipv4Addr::from_str(parts[0]).ok()?;
                let mask = parts[1].parse::<u8>().ok()?;
                let addr: u32 = u32::from(addr);
                let mask: u32 = !(0xffffffff >> mask);
                Some(Cidr {addr, mask})
            })
        })
        .collect();

    // Insert CIDRs into the HashMap
    for cidr in cidrs {
        cidr_map.set(cidr.addr & cidr.mask, 0);
    }

    let proxy = SAddrV4 {
        addr: u32::from_ne_bytes(args.proxy.ip().octets()).to_le(),
        port: (args.proxy.port() as u32).to_le(),
    };

    // Map the Server Address to the map
    HashMap::<SAddrV4, u8>::new(loaded.map("SERVERLIST")
        .expect("SERVERLIST map not found"))
        .unwrap()
        .set(proxy, /* dummy value */ 0);

    println!("Attach ddos_protection on interface: {} with mode {:?}", args.interface, xdp_mode);
    
    for program in loaded.xdps_mut() {
        program.attach_xdp(&args.interface, xdp_mode)
            .map_err(|err| {
                dbg!(&err);
                format!("{:?}", err)
            })?;
    }

    // exit without calling destructors so the probe is not unloaded
    std::process::exit(0);
}

// SPDX-License-Identifier: GPL-3.0
