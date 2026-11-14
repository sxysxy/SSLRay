//! Native OpenVPN interoperability against the isolated local Docker fixture.
//! Start only the OpenVPN service in tests/vpn-lab/compose.yaml before running
//! these ignored tests. They exchange IP packets through the encrypted tunnel
//! without creating a host TUN, changing host routes or storing passwords.
use anyhow::{Result, ensure};
use sslray_core::{
    config::{Profile, VpnProtocol},
    gateway::Gateway,
    openvpn,
};
use std::{
    net::Ipv4Addr,
    path::PathBuf,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

fn lab_profile() -> Result<Profile> {
    let state = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../work/openvpn-lab");
    ensure!(
        state.join("client.key").is_file(),
        "Start the isolated OpenVPN lab before this test"
    );
    let path = state.join("sslray-client.ovpn");
    std::fs::write(
        &path,
        "client\ndev tun\nproto udp4\nremote 127.0.0.1 1194\nnobind\nca ca.crt\ncert client.crt\nkey client.key\nremote-cert-tls server\nverify-x509-name sslray-server name\ntls-version-min 1.2\ndata-ciphers AES-256-GCM:AES-128-GCM\nauth SHA256\n",
    )?;
    Ok(Profile {
        protocol: VpnProtocol::OpenVpn,
        host: "127.0.0.1".into(),
        port: 1194,
        openvpn_config: path.to_string_lossy().into_owned(),
        ..Profile::default()
    })
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|p| u32::from(u16::from_be_bytes([p[0], *p.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn echo(source: Ipv4Addr, target: Ipv4Addr, sequence: u16) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0x53, 0x52];
    icmp.extend_from_slice(&sequence.to_be_bytes());
    icmp.extend_from_slice(b"SSLRay native OpenVPN interop");
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
#[ignore = "requires the local OpenVPN Docker service; no host route changes"]
fn native_certificate_auth_udp_and_encrypted_ip_round_trip() -> Result<()> {
    let profile = lab_profile()?;
    let mut prepared = openvpn::prepare(&profile)?;
    assert!(!format!("{prepared:?}").contains("PRIVATE KEY"));
    let result = Gateway::connect(&prepared, "", None);
    prepared.openvpn_config.zeroize();
    let mut gateway = result?;
    let result = (|| {
        ensure!(
            gateway.vip.octets()[..3] == [10, 88, 0],
            "Unexpected isolated lab address"
        );
        ensure!(
            gateway.outer_ipv4_addresses()? == [Ipv4Addr::LOCALHOST],
            "Outer peer must be the actual local server"
        );
        ensure!(
            gateway.routes.iter().any(|r| r == "10.88.0.0/24"),
            "Missing pushed tunnel network"
        );
        ensure!(
            gateway.cipher == "AES-256-GCM",
            "Unexpected negotiated data cipher"
        );
        ensure!(
            gateway.transport == "OpenVPN/UDP",
            "Unexpected negotiated transport"
        );
        let target = Ipv4Addr::new(10, 88, 0, 1);
        gateway.set_read_budget(Duration::from_millis(50))?;
        for sequence in 1..=5 {
            gateway.send_packet(&echo(gateway.vip, target, sequence))?;
            let deadline = Instant::now() + Duration::from_secs(1);
            while Instant::now() < deadline {
                gateway.keepalive()?;
                if let Some(packet) = gateway.read_packet()? {
                    let header = usize::from(packet[0] & 15) * 4;
                    if packet.len() >= header + 8
                        && packet[9] == 1
                        && packet[12..16] == target.octets()
                        && packet[header] == 0
                        && packet[header + 4..header + 6] == [0x53, 0x52]
                    {
                        return Ok(());
                    }
                }
            }
        }
        anyhow::bail!("No ICMP reply through the encrypted OpenVPN data channel")
    })();
    gateway.disconnect();
    result
}

#[test]
#[ignore = "requires the local OpenVPN Docker service; rejects its server identity"]
fn wrong_pinned_certificate_is_rejected_without_exposing_credentials() -> Result<()> {
    let mut profile = lab_profile()?;
    profile.certificate_sha256 = "00".repeat(32);
    let mut prepared = openvpn::prepare(&profile)?;
    let result = Gateway::connect(&prepared, "fixture-password-never-sent", None);
    prepared.openvpn_config.zeroize();
    ensure!(result.is_err(), "Wrong OpenVPN certificate pin must fail");
    let error = format!("{:#}", result.err().expect("checked error"));
    ensure!(
        !error.contains("fixture-password-never-sent") && !error.contains("PRIVATE KEY"),
        "OpenVPN errors must redact secrets"
    );
    Ok(())
}

#[test]
fn scripts_and_password_files_are_rejected_before_network_or_elevation() -> Result<()> {
    let state = std::env::temp_dir().join(format!("sslray-ovpn-import-{}", std::process::id()));
    std::fs::create_dir_all(&state)?;
    let run = (|| {
        for line in [
            "up /some/script fixture-secret",
            "plugin /some/library",
            "auth-user-pass password.txt",
            "remote-cert-ku a0",
            "tls-version-max 1.2",
            "tls-crypt-v2 secret.key",
        ] {
            let path = state.join("unsupported.ovpn");
            std::fs::write(
                &path,
                format!("client\ndev tun\nremote 127.0.0.1 1194 udp\n{line}\n"),
            )?;
            let profile = Profile {
                protocol: VpnProtocol::OpenVpn,
                openvpn_config: path.to_string_lossy().into_owned(),
                ..Profile::default()
            };
            let result = openvpn::prepare(&profile);
            ensure!(
                result.is_err(),
                "Unsupported security policy must fail closed"
            );
            ensure!(
                !format!("{:#}", result.expect_err("checked error")).contains("fixture-secret"),
                "Importer error echoed directive arguments"
            );
        }
        Ok(())
    })();
    std::fs::remove_dir_all(&state)?;
    run
}

#[test]
fn unsupported_config_does_not_call_otp_callback() {
    let mut prompted = false;
    let profile = Profile {
        protocol: VpnProtocol::OpenVpn,
        openvpn_config: "unprepared.ovpn".into(),
        ..Profile::default()
    };
    let result = Gateway::connect_with_challenge(&profile, "fixture-password", |_| {
        prompted = true;
        Ok(Zeroizing::new("fixture-otp".into()))
    });
    assert!(result.is_err());
    assert!(!prompted);
}
