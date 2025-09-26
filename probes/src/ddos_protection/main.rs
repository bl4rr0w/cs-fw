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

#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, LruHashMap},
    programs::XdpContext,
};
// Logging removed due to version conflicts

use probes::ddos_protection::SAddrV4;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};

const BYPASS_IPS: [u32; 4] = [
    152815192,
    765152566,
    3348974902,
    2128825654,
];

type Ipv4Addr = u32;
type DummyValue = u8;

const fn starts_with<const N: usize>(s: &[u8], needle: [u8; N]) -> bool {
    if s.len() < N {
        return false;
    }

    let mut i = 0;
    while i < N {
        if s[i] != needle[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[map(name = "SERVERLIST")]
static mut SERVERLIST: HashMap<SAddrV4, DummyValue> = HashMap::with_max_entries(256, 0);

#[map(name = "WHITELIST")]
static mut WHITELIST: LruHashMap<Ipv4Addr, DummyValue> = LruHashMap::with_max_entries(75_000_000, 0);

#[map(name = "TEMPLIST")]
static mut TEMPLIST: LruHashMap<Ipv4Addr, DummyValue> = LruHashMap::with_max_entries(75_000_000, 0);

const STEAM_PACKET_START: [u8; 4] = *b"\xff\xff\xff\xff";
const PACKET1_START: [u8; 6] = *b"\xff\xff\xff\xff\x67\x65";
const PACKET2_START: [u8; 9] = *b"\xff\xff\xff\xff\x63\x6f\x6e\x6e\x65";

#[xdp]
pub fn filter(ctx: XdpContext) -> u32 {
    match try_filter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_filter(ctx: XdpContext) -> Result<u32, u32> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dest_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    let ip_proto = unsafe { (*ipv4hdr).proto };

    match ip_proto {
        IpProto::Udp => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // Check bypass IPs
    if BYPASS_IPS.contains(&source_addr) {
        return Ok(xdp_action::XDP_PASS);
    }

    let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
    let source_port = u16::from_be(unsafe { (*udphdr).source });
    let dest_port = u16::from_be(unsafe { (*udphdr).dest });

    let source_socket_address = SAddrV4 {
        addr: source_addr,
        port: source_port as u32
    };
    let destination_socket_address = SAddrV4 {
        addr: dest_addr,
        port: dest_port as u32
    };

    // If packet is going from server to client, we will pass it.
    // If packet is not destined to a server, we will pass it.
    let server_check = unsafe {
        SERVERLIST.get(&source_socket_address).is_some() || SERVERLIST.get(&destination_socket_address).is_none()
    };
    if server_check {
        return Ok(xdp_action::XDP_PASS);
    }

    // Drop common UDP amplification source ports
    if source_port == 17 ||    // tftp
        source_port == 19 ||    // chargen
        source_port == 53 ||   // dns
        source_port == 111 ||  // rpcbind
        source_port == 123 ||  // ntp
        source_port == 137 ||  // netbios-ns
        source_port == 161 ||  // snmp
        source_port == 389 ||  // ldap
        source_port == 520 ||   // rip
        source_port == 751 ||   // kerberos
        source_port == 1434 ||  // ms-sql-s
        source_port == 1900 ||  // ssdp
        source_port == 5353 ||  // mdns
        source_port == 6881 ||  // bittorrent
        source_port == 11211 {  // memcached
        return Ok(xdp_action::XDP_DROP);
    }

    let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN;
    let payload_start = ctx.data() + payload_offset;
    let payload_end = ctx.data_end();

    if payload_start + STEAM_PACKET_START.len() + 1 > payload_end {
        return Ok(xdp_action::XDP_DROP);
    }

    let payload_data = unsafe {
        core::slice::from_raw_parts(payload_start as *const u8, (payload_end - payload_start) as usize)
    };

    if payload_data.len() < STEAM_PACKET_START.len() + 1 {
        return Ok(xdp_action::XDP_DROP);
    }

    let is_steam_packet = starts_with(&payload_data[STEAM_PACKET_START.len() + 1..], STEAM_PACKET_START);

    if is_steam_packet {
        if payload_data.len() < STEAM_PACKET_START.len() + 5 {
            return Ok(xdp_action::XDP_DROP);
        }

        let is_query_request_packet = match payload_data[STEAM_PACKET_START.len() + 4] {
            0x54 => true, // A2S_INFO_REQUEST
            0x56 => true, // A2S_RULES_REQUEST
            0x55 => true, // A2S_PLAYERS_REQUEST
            _ => false,
        };

        // A2S_RESPONSES ATTACK
        let is_illegitimate_request_packet = match payload_data[STEAM_PACKET_START.len() + 4] {
            0x49 => true, // A2S_INFO_RESPONSE
            0x45 => true, // A2S_RULES_RESPONSE
            0x44 => true, // A2S_PLAYERS_RESPONSE
            0x6d => true, // CSGO_UNKNOWN1_RESPONSE
            0x4c => true, // YOU_ARE_BANNED_RESPONSE
            _ => false,
        };

        if is_query_request_packet {
            return Ok(xdp_action::XDP_PASS);
        } else if is_illegitimate_request_packet {
            return Ok(xdp_action::XDP_DROP);
        }
    }

    let whitelist_check = unsafe { WHITELIST.get(&source_addr).is_some() };
    if whitelist_check {
        return Ok(xdp_action::XDP_PASS);
    }

    if payload_data.len() < PACKET1_START.len() {
        return Ok(xdp_action::XDP_DROP);
    }

    let is_packet1 = starts_with(&payload_data[PACKET1_START.len()..], PACKET1_START);

    if is_packet1 {
        let temp_check = unsafe { TEMPLIST.get(&source_addr).is_none() };
        return if temp_check {
            unsafe { let _ = TEMPLIST.insert(&source_addr, &0, 0); }
            Ok(xdp_action::XDP_PASS)
        } else {
            Ok(xdp_action::XDP_DROP)
        };
    }

    if payload_data.len() < PACKET2_START.len() {
        return Ok(xdp_action::XDP_DROP);
    }

    let is_packet2 = starts_with(&payload_data[PACKET2_START.len()..], PACKET2_START);

    if is_packet2 {
        let temp_exists = unsafe { TEMPLIST.get(&source_addr).is_some() };
        return if temp_exists {
            unsafe {
                let _ = TEMPLIST.remove(&source_addr);
                let _ = WHITELIST.insert(&source_addr, &0, 0);
            }
            Ok(xdp_action::XDP_PASS)
        } else {
            Ok(xdp_action::XDP_DROP)
        };
    }

    Ok(xdp_action::XDP_DROP)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, u32> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(xdp_action::XDP_ABORTED);
    }

    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

// SPDX-License-Identifier: GPL-3.0
