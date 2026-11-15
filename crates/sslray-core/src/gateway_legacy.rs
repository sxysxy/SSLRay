//! Legacy Huawei NEM framing and IPv4/TLS network extension.
//! Independent implementation from observed vendor formats. HTTP authentication
//! is provided separately by legacy_native; credentials never enter this module.
use super::{DataChannel, Decoder, FRAME_TIMEOUT, Gateway, valid_ipv4};
use crate::{
    config::{CryptoMode, Profile, TransportMode},
    crypto::{self, TlsStream},
    legacy_http::LegacyAuth,
};
use anyhow::{Context, Result, bail, ensure};
use std::{
    io::{self, Read, Write},
    net::Ipv4Addr,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: [u8; 8] = [0xfe, 0xfc, 0xef, 0xbe, 0xc1, 0x92, 0xa4, 0xd6];
#[path = "gateway_legacy_udp.rs"]
mod udp;
struct Frame {
    command: u16,
    payload: Zeroizing<Vec<u8>>,
}
#[derive(Debug)]
struct HandshakeTimeout(String);
impl std::fmt::Display for HandshakeTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Legacy gateway handshake timed out ({})", self.0)
    }
}
impl std::error::Error for HandshakeTimeout {}

#[derive(Debug)]
struct UdpUnavailable(&'static str);
impl std::fmt::Display for UdpUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for UdpUnavailable {}

const PENDING_UDP_KEY: u8 = 1;
const PENDING_UDP_PORT: u8 = 2;
const PENDING_TLS_SWITCH: u8 = 4;
#[derive(Default)]
struct LegacyDecoder {
    buffered: Vec<u8>,
    partial_since: Option<Instant>,
}
impl LegacyDecoder {
    fn payload_length(&self) -> usize {
        let bytes = [self.buffered[14], self.buffered[15]];
        let command = u16::from_be_bytes([self.buffered[12], self.buffered[13]]);
        // Observed company firmware sends ACL6's 20-byte response payload with
        // this one length word in host byte order. Other commands and all
        // requests retain network order; do not infer a general LE dialect.
        if command == 6 && bytes == [0x14, 0] {
            20
        } else {
            u16::from_be_bytes(bytes) as usize
        }
    }
    fn pending_summary(&self) -> String {
        if self.buffered.len() >= 16 {
            let mut summary = format!(
                "{} buffered frame bytes; {} bytes after first header; command {}; declared payload length BE {}, LE {}",
                self.buffered.len(),
                self.buffered.len() - 16,
                u16::from_be_bytes([self.buffered[12], self.buffered[13]]),
                u16::from_be_bytes([self.buffered[14], self.buffered[15]]),
                u16::from_le_bytes([self.buffered[14], self.buffered[15]])
            );
            // Diagnose a bounded set of plausible frame boundaries without
            // logging any user ID, session field or payload byte.
            for offset in [16usize, 20, 36] {
                let has_magic = self.buffered.get(offset..offset + 8) == Some(MAGIC.as_slice());
                summary.push_str(&format!("; next magic at {offset}: {has_magic}"));
                if has_magic && self.buffered.len() >= offset + 16 {
                    summary.push_str(&format!(
                        " (command {}, payload BE {}, LE {})",
                        u16::from_be_bytes([
                            self.buffered[offset + 12],
                            self.buffered[offset + 13]
                        ]),
                        u16::from_be_bytes([
                            self.buffered[offset + 14],
                            self.buffered[offset + 15]
                        ]),
                        u16::from_le_bytes([
                            self.buffered[offset + 14],
                            self.buffered[offset + 15]
                        ])
                    ));
                }
            }
            summary
        } else {
            format!("{} buffered frame bytes", self.buffered.len())
        }
    }
    fn read(&mut self, stream: &mut impl Read) -> Result<Option<Frame>> {
        loop {
            if self.buffered.len() >= 16 {
                ensure!(
                    self.buffered[..8] == MAGIC,
                    "Invalid legacy Huawei NEM framing"
                );
                let length = self.payload_length();
                if self.buffered.len() == length + 16 {
                    let result = Frame {
                        command: u16::from_be_bytes([self.buffered[12], self.buffered[13]]),
                        payload: Zeroizing::new(self.buffered[16..].to_vec()),
                    };
                    self.buffered.zeroize();
                    self.buffered.clear();
                    self.partial_since = None;
                    return Ok(Some(result));
                }
            }
            if let Some(start) = self.partial_since {
                ensure!(
                    start.elapsed() < FRAME_TIMEOUT,
                    "Legacy gateway frame timed out"
                );
            }
            let want = if self.buffered.len() < 16 {
                16 - self.buffered.len()
            } else {
                16 + self.payload_length() - self.buffered.len()
            };
            let mut buffer = [0; 4096];
            let take = want.min(buffer.len());
            match stream.read(&mut buffer[..take]) {
                Ok(0) => bail!("Legacy gateway closed the TLS tunnel"),
                Ok(n) => {
                    if self.buffered.is_empty() {
                        self.partial_since = Some(Instant::now());
                    }
                    self.buffered.extend_from_slice(&buffer[..n]);
                    buffer[..n].zeroize();
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Ok(None);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e).context("Reading legacy Huawei TLS tunnel"),
            }
        }
    }
}
impl Drop for LegacyDecoder {
    fn drop(&mut self) {
        self.buffered.zeroize();
    }
}
fn write_frame(stream: &mut impl Write, user_id: u32, command: u16, payload: &[u8]) -> Result<()> {
    let length = u16::try_from(payload.len()).context("Legacy frame payload too large")?;
    let mut header = [0; 16];
    header[..8].copy_from_slice(&MAGIC);
    header[8..12].copy_from_slice(&user_id.to_be_bytes());
    header[12..14].copy_from_slice(&command.to_be_bytes());
    header[14..].copy_from_slice(&length.to_be_bytes());
    // Match the vendor's single write for each complete legacy NEM frame. Some
    // older gateways process an SSL read as a message and reject a header-only
    // TLS record even though TCP itself permits arbitrary fragmentation.
    let mut frame = Zeroizing::new(Vec::with_capacity(header.len() + payload.len()));
    frame.extend_from_slice(&header);
    frame.extend_from_slice(payload);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}
fn receive(stream: &mut TlsStream, decoder: &mut LegacyDecoder, command: u16) -> Result<Frame> {
    for _ in 0..8 {
        let reply = decoder
            .read(stream)?
            .ok_or_else(|| HandshakeTimeout(decoder.pending_summary()))?;
        if reply.command == 7 {
            continue;
        }
        ensure!(
            reply.command != 8,
            "Legacy gateway terminated the VPN session during negotiation (kickout)"
        );
        ensure!(
            reply.command == command,
            "Legacy gateway returned command {} (expected {command})",
            reply.command
        );
        return Ok(reply);
    }
    bail!("Too many unsolicited legacy handshake frames")
}

fn receive_udp(stream: &mut TlsStream, decoder: &mut LegacyDecoder, command: u16) -> Result<Frame> {
    receive(stream, decoder, command).map_err(|error| {
        if error.is::<HandshakeTimeout>() {
            error.context(UdpUnavailable("Legacy UDP negotiation timed out"))
        } else {
            // Session termination, invalid framing and TLS errors are fatal;
            // they must not trigger another authentication or transport retry.
            error
        }
    })
}

fn negotiate_udp(
    stream: &mut TlsStream,
    decoder: &mut LegacyDecoder,
    user_id: u32,
    vip: Ipv4Addr,
    pending_replies: &mut u8,
) -> Result<udp::LegacyUdp> {
    // CHIV is requested with feature value4; the reply transport enum is3.
    // Never accept static-IV mode2 as a silent fallback.
    *pending_replies |= PENDING_UDP_KEY;
    write_frame(stream, user_id, 13, &4u32.to_be_bytes())?;
    let key_reply =
        receive_udp(stream, decoder, 13).context("Receiving legacy UDP key negotiation")?;
    *pending_replies &= !PENDING_UDP_KEY;
    if key_reply.payload.len() < 20 || u32_at(&key_reply.payload, 0)? != 3 {
        bail!(UdpUnavailable(
            "Gateway did not negotiate legacy CHIV UDP mode3"
        ));
    }
    let key = Zeroizing::new(key_reply.payload[4..20].try_into()?);
    *pending_replies |= PENDING_UDP_PORT;
    write_frame(stream, user_id, 26, &4u32.to_be_bytes())?;
    let port_reply =
        receive_udp(stream, decoder, 26).context("Receiving legacy UDP port negotiation")?;
    *pending_replies &= !PENDING_UDP_PORT;
    if port_reply.payload.len() < 2 {
        bail!(UdpUnavailable("Missing negotiated legacy UDP port"));
    }
    let port = u16::from_be_bytes([port_reply.payload[0], port_reply.payload[1]]);
    let mut peer = stream.get_ref().peer_addr()?;
    peer.set_port(port);
    let mut udp = udp::LegacyUdp::new(peer, vip, user_id, key)
        .context(UdpUnavailable("Legacy CHIV UDP could not be established"))?;
    udp.establish()
        .context(UdpUnavailable("Legacy CHIV UDP could not be established"))?;
    Ok(udp)
}
struct NetworkConfig {
    vip: Ipv4Addr,
    routes: Vec<String>,
    dns: Vec<Ipv4Addr>,
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(
        bytes
            .get(offset..offset + 4)
            .context("Truncated legacy network configuration")?
            .try_into()?,
    ))
}
fn prefix(mask: u32) -> Result<u32> {
    let p = mask.leading_ones();
    ensure!(
        mask == u32::MAX.checked_shl(32 - p).unwrap_or(0),
        "Legacy gateway sent noncontiguous netmask"
    );
    Ok(p)
}
fn network_config(bytes: &[u8]) -> Result<NetworkConfig> {
    // Older/newer structures differ by a four-byte field before route count.
    // Firmware uses either64 or1024 reserved route slots. Distinguish the
    // layouts by exact divisibility, then bound count by actual received slots.
    let count_at = [180usize, 184]
        .into_iter()
        .find(|offset| bytes.len() >= offset + 4 && (bytes.len() - offset - 4).is_multiple_of(12))
        .with_context(|| {
            format!(
                "Unsupported legacy network configuration size {}",
                bytes.len()
            )
        })?;
    let slots = (bytes.len() - count_at - 4) / 12;
    ensure!(
        slots <= 1024,
        "Legacy gateway reserved too many route slots"
    );
    let vip = Ipv4Addr::from(u32_at(bytes, 0)?);
    ensure!(
        !vip.is_unspecified() && !vip.is_broadcast() && !vip.is_multicast() && !vip.is_loopback(),
        "Legacy gateway did not assign a usable IPv4 address"
    );
    prefix(u32_at(bytes, 4)?)?;
    let count = u32_at(bytes, count_at)? as usize;
    ensure!(
        count <= slots,
        "Legacy gateway route count exceeds received slots"
    );
    let mut routes = Vec::new();
    for entry in bytes[count_at + 4..].chunks_exact(12).take(count) {
        let ip = u32_at(entry, 0)?;
        let mask = u32_at(entry, 4)?;
        let p = prefix(mask)?;
        ensure!(
            ip & !mask == 0,
            "Legacy gateway sent noncanonical IPv4 route"
        );
        let route = format!("{}/{p}", Ipv4Addr::from(ip));
        if !routes.contains(&route) {
            routes.push(route);
        }
    }
    let mut dns = Vec::new();
    for offset in [160, 164, 168] {
        let ip = Ipv4Addr::from(u32_at(bytes, offset)?);
        if !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast() && !dns.contains(&ip) {
            dns.push(ip);
        }
    }
    Ok(NetworkConfig { vip, routes, dns })
}

pub(super) struct LegacyChannel {
    stream: TlsStream,
    decoder: LegacyDecoder,
    user_id: u32,
    auth: Option<LegacyAuth>,
    profile: Profile,
    disconnected: bool,
    last_keepalive: Instant,
    last_control_read: Instant,
    udp: Option<udp::LegacyUdp>,
    pending_tls_controls: u8,
}
impl LegacyChannel {
    pub fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        ensure!(valid_ipv4(packet), "Malformed legacy outgoing IPv4 packet");
        if let Some(udp) = &mut self.udp {
            return udp.send_packet(packet);
        }
        write_frame(&mut self.stream, self.user_id, 2, packet)
    }
    pub fn read_packet(&mut self) -> Result<Option<Vec<u8>>> {
        if let Some(udp) = &mut self.udp {
            return match udp.receive()? {
                Some(udp::Datagram::Packet(packet)) => Ok(Some(packet)),
                _ => Ok(None),
            };
        }
        let Some(frame) = self.decoder.read(&mut self.stream)? else {
            return Ok(None);
        };
        let pending = match frame.command {
            13 => PENDING_UDP_KEY,
            26 => PENDING_UDP_PORT,
            16 => PENDING_TLS_SWITCH,
            _ => 0,
        };
        if self.pending_tls_controls & pending != 0 {
            // A timed-out UDP negotiation may reply after cmd16 was sent.
            // Consume only the specific outstanding responses, once each.
            self.pending_tls_controls &= !pending;
            return Ok(None);
        }
        match frame.command {
            2 => {
                ensure!(
                    valid_ipv4(&frame.payload),
                    "Malformed legacy gateway IPv4 packet"
                );
                Ok(Some(frame.payload.to_vec()))
            }
            7 => Ok(None),
            8 => bail!("Legacy gateway terminated the VPN session (kickout)"),
            command => bail!("Unsupported legacy tunnel command {command}"),
        }
    }
    pub fn keepalive(&mut self) -> Result<()> {
        if let Some(udp) = &mut self.udp {
            udp.keepalive()?;
            if self.last_control_read.elapsed() >= Duration::from_millis(500) {
                self.last_control_read = Instant::now();
                for _ in 0..8 {
                    let Some(frame) = self.decoder.read(&mut self.stream)? else {
                        break;
                    };
                    ensure!(
                        matches!(frame.command, 7 | 16),
                        "Legacy UDP control channel closed/rejected (command {})",
                        frame.command
                    );
                }
            }
        }
        if self.last_keepalive.elapsed() >= Duration::from_secs(10) {
            write_frame(&mut self.stream, self.user_id, 7, &[])?;
            self.last_keepalive = Instant::now();
        }
        Ok(())
    }
    pub fn set_read_budget(&self, budget: Duration) -> Result<()> {
        if let Some(udp) = &self.udp {
            udp.set_read_budget(budget)?;
        } else {
            self.stream.get_ref().set_read_timeout(Some(budget))?;
        }
        Ok(())
    }
    pub fn disconnect(&mut self) {
        self.close_channels();
        if !self.disconnected {
            self.disconnected = true;
            if let Some(auth) = &self.auth {
                let _ = logout(&self.profile, auth);
            }
        }
    }
    pub fn close_channels(&mut self) {
        let _ = self.stream.get_ref().shutdown(std::net::Shutdown::Both);
    }
    pub fn outer_ipv4_addresses(&self) -> Result<Vec<Ipv4Addr>> {
        let mut peers = vec![self.stream.get_ref().peer_addr()?];
        if let Some(udp) = &self.udp {
            peers.push(udp.peer_addr()?);
        }
        Ok(peers
            .into_iter()
            .filter_map(|p| match p.ip() {
                std::net::IpAddr::V4(ip) => Some(ip),
                _ => None,
            })
            .collect())
    }
}

pub(super) fn connect(
    profile: &Profile,
    auth_stream: TlsStream,
    auth: LegacyAuth,
    status: &mut dyn FnMut(&str),
) -> Result<Gateway> {
    match connect_inner(profile, auth_stream, auth.user_id, auth.random_id, status) {
        Ok(mut gateway) => {
            if let DataChannel::Legacy(channel) = &mut gateway.data {
                channel.auth = Some(auth);
            }
            Ok(gateway)
        }
        Err(error) => {
            let _ = logout(profile, &auth);
            Err(error)
        }
    }
}

fn logout(profile: &Profile, auth: &LegacyAuth) -> Result<()> {
    if auth.native_auth {
        crate::legacy_http::logout_native(
            profile,
            auth.user_id,
            auth.random_id,
            auth.vtid,
            &auth.cookie,
        )
    } else {
        crate::legacy_http::logout(profile, auth.user_id, &auth.cookie)
    }
}

fn connect_inner(
    profile: &Profile,
    auth_stream: TlsStream,
    user_id: u32,
    session_id: u32,
    status: &mut dyn FnMut(&str),
) -> Result<Gateway> {
    ensure!(
        user_id != 0,
        "Legacy authentication returned invalid user ID"
    );
    let authenticated_certificate = auth_stream
        .ssl()
        .peer_certificate()
        .context("No legacy auth peer certificate")?
        .to_der()?;
    // Match the observed native lifecycle: complete and close authentication
    // before creating the independent NEM connection. Keep session metadata,
    // rather than the authentication socket, for explicit logout.
    let _ = auth_stream.get_ref().shutdown(std::net::Shutdown::Both);
    drop(auth_stream);
    let mut stream = crypto::connect(profile)?;
    ensure!(
        stream
            .ssl()
            .peer_certificate()
            .context("No legacy data peer certificate")?
            .to_der()?
            == authenticated_certificate,
        "Legacy auth and tunnel peer identities differ"
    );
    stream
        .get_ref()
        .set_read_timeout(Some(Duration::from_secs(15)))?;
    stream
        .get_ref()
        .set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut decoder = LegacyDecoder::default();
    // Legacy firmware requires ACL/session binding before IPv4 allocation.
    // A REQVIP reply by itself does not establish an authenticated data path.
    // Match the native packer's initialized reserved word. SessionID remains
    // separate authentication/logout metadata. Send one complete TLS record.
    write_frame(&mut stream, user_id, 6, &0u32.to_be_bytes())
        .context("Sending legacy ACL session binding")?;
    let _acl = receive(&mut stream, &mut decoder, 6).with_context(|| {
        format!(
            "Receiving legacy ACL session binding response (authentication SessionID present: {})",
            session_id != 0
        )
    })?;
    write_frame(&mut stream, user_id, 3, &[]).context("Requesting legacy IPv4 allocation")?;
    let reply =
        receive(&mut stream, &mut decoder, 3).context("Receiving legacy IPv4 allocation")?;
    let config = network_config(&reply.payload)?;
    let mut pending_tls_controls = 0;
    let udp = if legacy_udp_enabled(profile) {
        status("Negotiating Huawei legacy CHIV UDP");
        if profile.transport == TransportMode::Auto {
            stream
                .get_ref()
                .set_read_timeout(Some(Duration::from_secs(3)))?;
        }
        match negotiate_udp(
            &mut stream,
            &mut decoder,
            user_id,
            config.vip,
            &mut pending_tls_controls,
        ) {
            Ok(udp) => {
                status("Huawei legacy CHIV UDP established");
                Some(udp)
            }
            Err(error)
                if profile.transport == TransportMode::Auto && error.is::<UdpUnavailable>() =>
            {
                status("Huawei legacy UDP unavailable; switching to TLS");
                // Match native fallback: write cmd16 on the same authenticated
                // NEM TLS connection. No mandatory ACK has been observed; an
                // optional reply and late key/port responses are drained later.
                write_frame(&mut stream, user_id, 16, &[])
                    .context("Switching legacy UDP transport back to TLS")?;
                pending_tls_controls |= PENDING_TLS_SWITCH;
                status("Huawei legacy TLS selected");
                None
            }
            Err(error) => return Err(error),
        }
    } else {
        if profile.crypto == CryptoMode::GmTls13 {
            status("GM TLS policy excludes legacy UDP");
        }
        status("Huawei legacy TLS selected");
        None
    };
    let tls_cipher = stream
        .ssl()
        .current_cipher()
        .map(|c| format!("{} {}", stream.ssl().version_str(), c.name()))
        .unwrap_or_default();
    let cipher = if udp.is_some() {
        format!("AES-128-CBC (CHIV; no packet MAC); control {tls_cipher}")
    } else {
        tls_cipher
    };
    stream
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(1)))?;
    let now = Instant::now();
    Ok(Gateway {
        vip: config.vip,
        negotiated_mtu: None,
        routes: config.routes,
        dns: config.dns,
        cipher,
        transport: if udp.is_some() {
            "UDP/AES-128-CBC (legacy, unauthenticated)"
        } else {
            "TLS/TCP (Huawei legacy)"
        }
        .into(),
        data: DataChannel::Legacy(Box::new(LegacyChannel {
            stream,
            decoder,
            user_id,
            auth: None,
            profile: profile.clone(),
            disconnected: false,
            last_keepalive: now,
            last_control_read: now,
            udp,
            pending_tls_controls,
        })),
        control: None,
        control_decoder: Decoder::default(),
        token: Zeroizing::new(Vec::new()),
        started: now,
        last_control_keepalive: now,
        last_control_read: now,
        last_data_keepalive: now,
    })
}

fn legacy_udp_enabled(profile: &Profile) -> bool {
    profile.crypto == CryptoMode::Standard && profile.transport != TransportMode::Tls
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_udp_selection_uses_negotiated_transport_and_crypto_not_old_flag() {
        for allow_legacy_udp in [false, true] {
            for transport in [TransportMode::Auto, TransportMode::Tls, TransportMode::Udp] {
                let mut profile = Profile {
                    transport,
                    allow_legacy_udp,
                    ..Profile::default()
                };
                assert_eq!(
                    legacy_udp_enabled(&profile),
                    transport != TransportMode::Tls
                );
                profile.crypto = CryptoMode::GmTls13;
                assert!(!legacy_udp_enabled(&profile));
            }
        }
    }
    #[test]
    fn fixed_network_config_checks_count_masks_and_networks() {
        let mut bytes = vec![0; 12476];
        bytes[..4].copy_from_slice(&[10, 0, 0, 2]);
        bytes[4..8].copy_from_slice(&[255, 255, 255, 0]);
        bytes[184..188].copy_from_slice(&1u32.to_be_bytes());
        bytes[188..192].copy_from_slice(&[10, 1, 0, 0]);
        bytes[192..196].copy_from_slice(&[255, 255, 0, 0]);
        let config = network_config(&bytes).unwrap();
        assert_eq!(config.routes, ["10.1.0.0/16"]);
        bytes[190] = 1;
        assert!(network_config(&bytes).is_err());
        bytes[190] = 0;
        bytes[184..188].copy_from_slice(&1025u32.to_be_bytes());
        assert!(network_config(&bytes).is_err());
    }
    #[test]
    fn legacy_64_route_configuration_956_bytes() {
        let mut bytes = vec![0; 956];
        bytes[..4].copy_from_slice(&[10, 0, 0, 2]);
        bytes[4..8].copy_from_slice(&[255, 255, 255, 0]);
        bytes[184..188].copy_from_slice(&1u32.to_be_bytes());
        bytes[188..192].copy_from_slice(&[172, 16, 0, 0]);
        bytes[192..196].copy_from_slice(&[255, 240, 0, 0]);
        assert_eq!(network_config(&bytes).unwrap().routes, ["172.16.0.0/12"]);
        bytes[184..188].copy_from_slice(&65u32.to_be_bytes());
        assert!(network_config(&bytes).is_err());
    }
    #[test]
    fn legacy_frame_roundtrip_and_truncated_body() {
        let mut data = Vec::new();
        write_frame(&mut data, 0x123456, 3, b"payload").unwrap();
        let frame = LegacyDecoder::default()
            .read(&mut &data[..])
            .unwrap()
            .unwrap();
        assert_eq!(frame.command, 3);
        assert_eq!(frame.payload.as_slice(), b"payload");
        assert!(
            LegacyDecoder::default()
                .read(&mut &data[..data.len() - 1])
                .is_err()
        );
    }
    #[test]
    fn acl_response_length_quirk_keeps_following_frame_boundary() {
        for length_word in [[0, 20], [20, 0]] {
            let mut wire = Vec::new();
            write_frame(&mut wire, 42, 6, &[0; 20]).unwrap();
            wire[14..16].copy_from_slice(&length_word);
            write_frame(&mut wire, 42, 7, &[]).unwrap();
            let mut reader = io::Cursor::new(wire);
            let mut decoder = LegacyDecoder::default();
            let acl = decoder.read(&mut reader).unwrap().unwrap();
            assert_eq!(acl.command, 6);
            assert_eq!(acl.payload.len(), 20);
            assert_eq!(reader.position(), 36);
            let following = decoder.read(&mut reader).unwrap().unwrap();
            assert_eq!(following.command, 7);
            assert!(following.payload.is_empty());
            assert_eq!(reader.position(), 52);
        }
        let mut other_command = LegacyDecoder::default();
        write_frame(&mut other_command.buffered, 42, 3, &[0; 20]).unwrap();
        other_command.buffered[14..16].copy_from_slice(&[20, 0]);
        assert_eq!(other_command.payload_length(), 5120);
    }
}
