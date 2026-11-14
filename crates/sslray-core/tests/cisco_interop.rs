//! Real ocserv interoperability, confined to the optional loopback Docker lab.
use anyhow::{Result, ensure};
use sslray_core::{
    config::{Profile, VpnProtocol},
    gateway::Gateway,
};
use std::{
    net::Ipv4Addr,
    path::PathBuf,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

fn lab() -> Result<(Profile, Zeroizing<String>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../work/ocserv-lab");
    let profile: Profile = serde_json::from_slice(&std::fs::read(dir.join("profile.json"))?)?;
    ensure!(
        profile.protocol == VpnProtocol::Cisco
            && profile.host == "127.0.0.1"
            && profile.port == 1443,
        "Cisco interop is restricted to the loopback lab"
    );
    let password = Zeroizing::new(std::fs::read_to_string(dir.join("password"))?);
    let password = Zeroizing::new(password.trim_end().to_owned());
    Ok((profile, password))
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|p| u32::from(u16::from_be_bytes([p[0], *p.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16)
    }
    !(sum as u16)
}
fn echo(source: Ipv4Addr, target: Ipv4Addr, sequence: u16) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0x53, 0x52];
    icmp.extend_from_slice(&sequence.to_be_bytes());
    icmp.extend_from_slice(b"SSLRay native CSTP interop");
    let check = checksum(&icmp);
    icmp[2..4].copy_from_slice(&check.to_be_bytes());
    let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 1, 0, 0];
    packet[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&source.octets());
    packet.extend_from_slice(&target.octets());
    let check = checksum(&packet);
    packet[10..12].copy_from_slice(&check.to_be_bytes());
    packet.extend_from_slice(&icmp);
    packet
}
#[test]
#[ignore = "requires sslray-ocserv-lab at127.0.0.1:1443; no host interface or routes"]
fn real_ocserv_password_cstp_and_encrypted_ip_round_trip() -> Result<()> {
    let (profile, password) = lab()?;
    let mut gateway = Gateway::connect(&profile, &password, None)?;
    let result = (|| {
        ensure!(
            gateway.vip.octets()[..3] == [10, 91, 0],
            "Unexpected isolated lab address"
        );
        ensure!(
            gateway.outer_ipv4_addresses()? == [Ipv4Addr::LOCALHOST],
            "Outer peer must be the actual local server"
        );
        ensure!(
            gateway.routes.iter().any(|r| r == "10.91.0.0/24"),
            "Missing server-pushed route"
        );
        ensure!(
            gateway.transport.contains("CSTP"),
            "Unexpected tunnel transport"
        );
        let target = Ipv4Addr::new(10, 91, 0, 1);
        gateway.set_read_budget(Duration::from_millis(50))?;
        for seq in 1..=5 {
            gateway.send_packet(&echo(gateway.vip, target, seq))?;
            let deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < deadline {
                gateway.keepalive()?;
                if let Some(packet) = gateway.read_packet()? {
                    let h = usize::from(packet[0] & 15) * 4;
                    if packet.len() >= h + 8
                        && packet[9] == 1
                        && packet[12..16] == target.octets()
                        && packet[h] == 0
                        && packet[h + 4..h + 6] == [0x53, 0x52]
                    {
                        return Ok(());
                    }
                }
            }
        }
        anyhow::bail!("No ICMP reply through the encrypted CSTP channel")
    })();
    gateway.disconnect();
    result
}
#[test]
#[ignore = "requires sslray-ocserv-lab; reject TLS identity before credentials"]
fn real_ocserv_wrong_pin_rejected() -> Result<()> {
    let (mut profile, password) = lab()?;
    profile.certificate_sha256 = "00".repeat(32);
    let result = Gateway::connect(&profile, &password, None);
    ensure!(result.is_err(), "Wrong pin must be rejected");
    let error = format!("{:#}", result.err().expect("checked error"));
    ensure!(
        error.contains("SHA-256 mismatch") && !error.contains(password.as_str()),
        "Expected redacted certificate failure"
    );
    Ok(())
}
