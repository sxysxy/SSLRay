//! Sends a bounded DNS probe through an authenticated VPN without creating interfaces
//! or changing routes. Password is read from a hidden terminal prompt or stdin. No credentials or session tokens are printed.
//!
//! cargo run -p sslray-core --example probe_data -- /path/to/profile.json
use anyhow::{Context, Result, bail, ensure};
use sslray_core::{config::Profile, gateway::Gateway};
use std::{
    io::{self, BufRead, IsTerminal, Read, Write},
    net::Ipv4Addr,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

fn checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for word in header.chunks(2) {
        sum += u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn query_packet(vip: Ipv4Addr, dns: Ipv4Addr, port: u16, id: [u8; 2]) -> Vec<u8> {
    // DNS: recursive A/IN query for example.com, with a per-run transaction ID.
    let mut query = vec![id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    query.extend_from_slice(b"\x07example\x03com\0\0\x01\0\x01");
    let udp_size = 8 + query.len();
    let mut packet = vec![0u8; 20 + udp_size];
    packet[0] = 0x45;
    let ip_size = packet.len() as u16;
    packet[2..4].copy_from_slice(&ip_size.to_be_bytes());
    packet[4..6].copy_from_slice(&id);
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't fragment.
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&vip.octets());
    packet[16..20].copy_from_slice(&dns.octets());
    let ip_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&port.to_be_bytes());
    packet[22..24].copy_from_slice(&53u16.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_size as u16).to_be_bytes());
    // A zero UDP checksum is explicitly permitted for IPv4 UDP packets.
    packet[28..].copy_from_slice(&query);
    packet
}

fn matched_response(
    packet: &[u8],
    vip: Ipv4Addr,
    dns: Ipv4Addr,
    port: u16,
    id: [u8; 2],
) -> Option<(u8, u16)> {
    if packet.len() < 40 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return None;
    }
    let ihl = usize::from(packet[0] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if ihl < 20 || total != packet.len() || ihl + 20 > total {
        return None;
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if fragment & 0x3fff != 0 || packet[12..16] != dns.octets() || packet[16..20] != vip.octets() {
        return None;
    }
    let udp = &packet[ihl..];
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if u16::from_be_bytes([udp[0], udp[1]]) != 53
        || u16::from_be_bytes([udp[2], udp[3]]) != port
        || udp_len != udp.len()
        || udp_len < 20
    {
        return None;
    }
    let response = &udp[8..];
    if response[..2] != id || response[2] & 0x80 == 0 {
        return None;
    }
    Some((
        response[3] & 15,
        u16::from_be_bytes([response[6], response[7]]),
    ))
}

fn probe(gateway: &mut Gateway) -> Result<()> {
    let Some(dns) = gateway.dns.iter().copied().find(|ip| {
        !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast() && !ip.is_loopback()
    }) else {
        println!(
            "{}",
            serde_json::json!({"probe":"skipped","reason":"Gateway did not advertise a usable DNS server","network_changed":false})
        );
        return Ok(());
    };
    let mut random = [0u8; 4];
    openssl::rand::rand_bytes(&mut random)?;
    let id = [random[0], random[1]];
    let port = 49152 + (u16::from_be_bytes([random[2], random[3]]) & 0x3fff);
    let packet = query_packet(gateway.vip, dns, port, id);
    gateway.set_read_budget(Duration::from_millis(100))?;
    gateway.send_packet(&packet)?;
    println!(
        "{}",
        serde_json::json!({"probe":"sent","destination":dns.to_string(),"port":53,"query":"example.com A","bytes":packet.len(),"network_changed":false})
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut attempts = 1;
    let mut last_sent = Instant::now();
    while Instant::now() < deadline {
        gateway.keepalive()?;
        if let Some(packet) = gateway.read_packet()?
            && let Some((rcode, answers)) = matched_response(&packet, gateway.vip, dns, port, id)
        {
            println!(
                "{}",
                serde_json::json!({"probe":"received","destination":dns.to_string(),"rcode":rcode,"answers":answers,"bytes":packet.len(),"network_changed":false})
            );
            return Ok(());
        }
        if attempts < 3 && last_sent.elapsed() >= Duration::from_secs(1) {
            gateway.send_packet(&packet)?;
            attempts += 1;
            last_sent = Instant::now();
        }
    }
    bail!(
        "DNS probe timed out after 5 seconds; authentication succeeded but no matching VPN data reply arrived"
    )
}

fn probe_icmp(gateway: &mut Gateway, target: Ipv4Addr) -> Result<()> {
    ensure!(
        !target.is_unspecified()
            && !target.is_broadcast()
            && !target.is_multicast()
            && !target.is_loopback(),
        "Select a usable remote IPv4 address"
    );
    let mut id = [0u8; 2];
    openssl::rand::rand_bytes(&mut id)?;
    let mut body = vec![8, 0, 0, 0, id[0], id[1], 0, 1];
    body.extend_from_slice(b"SSLRay reachability probe");
    let check = checksum(&body);
    body[2..4].copy_from_slice(&check.to_be_bytes());
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((20 + body.len()) as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 1;
    packet[12..16].copy_from_slice(&gateway.vip.octets());
    packet[16..20].copy_from_slice(&target.octets());
    let check = checksum(&packet);
    packet[10..12].copy_from_slice(&check.to_be_bytes());
    packet.extend_from_slice(&body);
    gateway.set_read_budget(Duration::from_millis(100))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut attempts = 0;
    let mut last_sent = None::<Instant>;
    while Instant::now() < deadline {
        if attempts < 3 && last_sent.is_none_or(|last| last.elapsed() >= Duration::from_secs(1)) {
            gateway.send_packet(&packet)?;
            attempts += 1;
            last_sent = Some(Instant::now());
        }
        gateway.keepalive()?;
        if let Some(reply) = gateway.read_packet()? {
            let header = usize::from(reply[0] & 15) * 4;
            if reply.len() >= header + 8
                && reply[9] == 1
                && reply[12..16] == target.octets()
                && reply[16..20] == gateway.vip.octets()
                && reply[header] == 0
                && reply[header + 4..header + 6] == id
                && reply[header + 6..header + 8] == [0, 1]
            {
                println!(
                    "{}",
                    serde_json::json!({"probe":"icmp_reply","target":target.to_string(),"bytes":reply.len(),"attempts":attempts,"network_changed":false})
                );
                return Ok(());
            }
        }
    }
    bail!("No matching ICMP echo reply through this VPN connection after 3 bounded probes")
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let path = args.next().context(
        "Usage: probe_data <profile.json> [ICMP-target-IPv4]; password is read from stdin",
    )?;
    let icmp_target = args
        .next()
        .map(|s| {
            s.to_str()
                .context("ICMP target must be text")?
                .parse::<Ipv4Addr>()
                .context("ICMP target must be an IPv4 address")
        })
        .transpose()?;
    ensure!(
        args.next().is_none(),
        "Only a profile and optional ICMP target are accepted; do not pass passwords in arguments"
    );
    let profile: Profile = serde_json::from_slice(&std::fs::read(path)?)?;
    profile.validate()?;
    let mut password = if io::stdin().is_terminal() {
        Zeroizing::new(rpassword::prompt_password("VPN password: ")?)
    } else {
        eprint!("VPN password (stdin): ");
        io::stderr().flush()?;
        let mut input = Zeroizing::new(Vec::new());
        io::stdin()
            .lock()
            .take(1026)
            .read_until(b'\n', &mut input)?;
        while matches!(input.last(), Some(b'\r' | b'\n')) {
            input.pop();
        }
        ensure!(
            !input.is_empty() && input.len() <= 1024,
            "Password must be 1..1024 bytes"
        );
        Zeroizing::new(String::from_utf8(input.to_vec()).context("Password must be UTF-8")?)
    };
    let connection = Gateway::connect(&profile, &password, None);
    password.zeroize();
    let mut gateway = connection?;
    println!(
        "{}",
        serde_json::json!({"authenticated":true,"transport":gateway.transport,"vip":gateway.vip.to_string(),"cipher":gateway.cipher,"dns_count":gateway.dns.len(),"route_count":gateway.routes.len(),"network_changed":false})
    );
    let result = if let Some(target) = icmp_target {
        probe_icmp(&mut gateway, target)
    } else {
        probe(&mut gateway)
    };
    // Explicit logout/close also runs when the data probe fails or has no target.
    gateway.disconnect();
    result
}
