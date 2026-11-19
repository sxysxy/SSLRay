//! Huawei/SecoClient legacy and NEM v1 authentication and IPv4 tunnels.
//! Wire observations: Bruce-lhq/univpn-connect, docs/protocol.md and the MIT
//! licensed Python reference. This is an independent Rust implementation.
use crate::{
    backend::{BackendConnection, PacketBackend},
    config::{CryptoMode, Profile, TransportMode, VpnProtocol},
    crypto::{self, TlsStream},
};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Write},
    net::Ipv4Addr,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: [u8; 4] = [0xc1, 0x92, 0xa4, 0xd6];
const FRAME_TIMEOUT: Duration = Duration::from_secs(30);

#[path = "gateway_legacy.rs"]
mod legacy;
#[path = "gateway_udp.rs"]
mod udp;

struct Frame {
    command: u8,
    payload: Zeroizing<Vec<u8>>,
}

#[derive(Default)]
struct Decoder {
    buffered: Vec<u8>,
    partial_since: Option<Instant>,
}
impl Decoder {
    fn read(&mut self, stream: &mut impl Read) -> Result<Option<Frame>> {
        loop {
            if self.buffered.len() >= 8 {
                ensure!(
                    self.buffered[..4] == MAGIC && self.buffered[4] == 1,
                    "Gateway returned unsupported NEM framing"
                );
                let size = u16::from_be_bytes([self.buffered[6], self.buffered[7]]) as usize;
                if self.buffered.len() >= size + 8 {
                    let frame = Frame {
                        command: self.buffered[5],
                        payload: Zeroizing::new(self.buffered[8..8 + size].to_vec()),
                    };
                    self.buffered[..8 + size].zeroize();
                    self.buffered.drain(..8 + size);
                    self.partial_since = if self.buffered.is_empty() {
                        None
                    } else {
                        Some(Instant::now())
                    };
                    return Ok(Some(frame));
                }
            }
            if let Some(start) = self.partial_since {
                ensure!(
                    start.elapsed() < FRAME_TIMEOUT,
                    "Gateway frame body timed out"
                );
            }
            // Read only enough for one frame. This also bounds memory for an adversarial peer.
            let want = if self.buffered.len() < 8 {
                8 - self.buffered.len()
            } else {
                8 + u16::from_be_bytes([self.buffered[6], self.buffered[7]]) as usize
                    - self.buffered.len()
            };
            let mut chunk = [0u8; 4096];
            let limit = want.min(chunk.len());
            match stream.read(&mut chunk[..limit]) {
                Ok(0) => bail!("Gateway closed the TLS channel"),
                Ok(n) => {
                    if self.buffered.is_empty() {
                        self.partial_since = Some(Instant::now());
                    }
                    self.buffered.extend_from_slice(&chunk[..n]);
                    chunk[..n].zeroize();
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
                Err(e) => return Err(e).context("Reading gateway TLS channel"),
            }
        }
    }
}
impl Drop for Decoder {
    fn drop(&mut self) {
        self.buffered.zeroize();
    }
}

fn write_frame(stream: &mut impl Write, command: u8, payload: &[u8]) -> Result<()> {
    let length = u16::try_from(payload.len()).context("NEM payload exceeds 65535 bytes")?;
    let mut header = [0u8; 8];
    header[..4].copy_from_slice(&MAGIC);
    header[4] = 1;
    header[5] = command;
    header[6..].copy_from_slice(&length.to_be_bytes());
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}
fn receive(stream: &mut TlsStream, decoder: &mut Decoder, expected: u8) -> Result<Frame> {
    let frame = decoder
        .read(stream)?
        .context("Gateway handshake timed out")?;
    ensure!(
        frame.command == expected,
        "Unexpected gateway response command 0x{:02x} (expected 0x{expected:02x})",
        frame.command
    );
    Ok(frame)
}

enum FirstReply {
    V1,
    Legacy(Zeroizing<Vec<u8>>),
}
fn receive_first(stream: &mut TlsStream) -> Result<FirstReply> {
    let mut first = [0; 8];
    stream.read_exact(&mut first)?;
    if first[..4] == MAGIC {
        ensure!(
            first[4] == 1 && first[5] == 0 && first[6..] == [0, 4],
            "Unsupported NEM v1 FirstConnect response"
        );
        let mut status = [0; 4];
        stream.read_exact(&mut status)?;
        ensure!(status == [0; 4], "Gateway rejected NEM v1 FirstConnect");
        Ok(FirstReply::V1)
    } else {
        ensure!(
            first == [0xfe, 0xfc, 0xef, 0xbe, 0xc1, 0x92, 0xa4, 0xd6],
            "Gateway returned unsupported FirstConnect framing"
        );
        let mut rest = [0; 8];
        stream.read_exact(&mut rest)?;
        ensure!(
            u16::from_be_bytes([rest[4], rest[5]]) == 0x1d,
            "Unexpected legacy FirstConnect command"
        );
        let length = u16::from_be_bytes([rest[6], rest[7]]) as usize;
        ensure!(
            (24..=8192).contains(&length),
            "Unsupported legacy FirstConnect response size"
        );
        let mut payload = Zeroizing::new(vec![0; length]);
        stream.read_exact(&mut payload)?;
        Ok(FirstReply::Legacy(payload))
    }
}
fn first_connect(domain: &str) -> Result<Vec<u8>> {
    ensure!(
        domain.len() <= 256 && !domain.contains('\0'),
        "Authentication domain exceeds 256 bytes or contains NUL"
    );
    let mut request = vec![0u8; 340];
    request[..4].copy_from_slice(&[0xfe, 0xfc, 0xef, 0xbe]);
    request[4..8].copy_from_slice(&MAGIC);
    request[12..16].copy_from_slice(&[0x00, 0x1d, 0x01, 0x44]);
    // The native macOS packer copies its 64-byte OS field at wire offset16,
    // then the 256-byte domain at offset80. Preserve its platform identification
    // instead of sending an unspecified OS on legacy firmware.
    #[cfg(target_os = "macos")]
    request[16..21].copy_from_slice(b"Mac64");
    request[80..80 + domain.len()].copy_from_slice(domain.as_bytes());
    request[336..].copy_from_slice(&[0, 1, 0, 0]);
    Ok(request)
}
fn append_tlv(out: &mut Vec<u8>, kind: u16, value: &[u8]) -> Result<()> {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(
        &u16::try_from(value.len())
            .context("Authentication field too long")?
            .to_be_bytes(),
    );
    out.extend_from_slice(value);
    Ok(())
}
fn escaped(value: &str) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(value.len() + 1));
    for b in value.bytes() {
        match b {
            b'%' => out.extend_from_slice(b"%25"),
            b'&' => out.extend_from_slice(b"%26"),
            b'+' => out.extend_from_slice(b"%2B"),
            b => out.push(b),
        }
    }
    out.push(0);
    out
}
fn tlvs(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        ensure!(bytes.len() >= 4, "Truncated gateway TLV header");
        let kind = u16::from_be_bytes([bytes[0], bytes[1]]);
        let len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        ensure!(bytes.len() >= 4 + len, "Truncated gateway TLV value");
        result.push((kind, &bytes[4..4 + len]));
        bytes = &bytes[4 + len..];
    }
    Ok(result)
}
pub(crate) fn valid_ipv4(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return false;
    }
    let ihl = (packet[0] & 15) as usize * 4;
    ihl >= 20
        && ihl <= packet.len()
        && u16::from_be_bytes([packet[2], packet[3]]) as usize == packet.len()
}

/// An authentication result that the UI can distinguish from a network error.
#[derive(Debug)]
pub enum AuthError {
    ChallengeRequired,
    UnsupportedMethod(u8),
    Rejected(u32),
}
impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChallengeRequired => {
                f.write_str("Gateway requests an SMS/temporary secondary password")
            }
            Self::UnsupportedMethod(method) => write!(
                f,
                "Unsupported gateway secondary authentication method {method}"
            ),
            Self::Rejected(status) => {
                write!(f, "Gateway rejected authentication (status {status})")
            }
        }
    }
}
impl std::error::Error for AuthError {}

fn sms_payload(otp: &str) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        !otp.is_empty() && otp.len() <= 31 && !otp.contains('\0'),
        "Temporary password must contain 1..31 UTF-8 bytes without NUL"
    );
    let mut payload = Zeroizing::new(vec![0; 33]);
    payload[0] = 1;
    payload[1..1 + otp.len()].copy_from_slice(otp.as_bytes());
    Ok(payload)
}

fn switch_transport(
    stream: &mut TlsStream,
    decoder: &mut Decoder,
    token: &[u8],
    mode: u8,
) -> Result<()> {
    let mut payload = Zeroizing::new(token.to_vec());
    payload.push(mode);
    write_frame(stream, 0x09, &payload)?;
    let reply = receive(stream, decoder, 0x09)?;
    ensure!(
        reply.payload.as_slice() == [0],
        "Gateway rejected requested tunnel transport mode"
    );
    Ok(())
}

/// One authenticated VPN session; it must remain owned by the network worker.
/// Dropping it closes both live TLS channels and erases the authentication token.
pub struct Gateway {
    pub vip: Ipv4Addr,
    pub routes: Vec<String>,
    pub dns: Vec<Ipv4Addr>,
    pub cipher: String,
    pub transport: String,
    pub negotiated_mtu: Option<u16>,
    data: DataChannel,
    control: Option<TlsStream>,
    control_decoder: Decoder,
    token: Zeroizing<Vec<u8>>,
    started: Instant,
    last_control_keepalive: Instant,
    last_control_read: Instant,
    last_data_keepalive: Instant,
}
enum DataChannel {
    Tls { stream: TlsStream, decoder: Decoder },
    Udp(udp::UdpChannel),
    Legacy(Box<legacy::LegacyChannel>),
    External(Box<dyn PacketBackend>),
}
impl Gateway {
    pub(crate) fn from_backend(connection: BackendConnection) -> Result<Self> {
        if let Some(mtu) = connection.negotiated_mtu {
            ensure!(
                (576..=1500).contains(&mtu),
                "VPN server negotiated an unsupported MTU"
            );
        }
        ensure!(
            !connection.vip.is_unspecified()
                && !connection.vip.is_multicast()
                && !connection.vip.is_broadcast()
                && !connection.vip.is_loopback(),
            "VPN server assigned an unusable IPv4 address"
        );
        let now = Instant::now();
        Ok(Self {
            vip: connection.vip,
            routes: connection.routes,
            dns: connection.dns,
            cipher: connection.cipher,
            transport: connection.transport,
            negotiated_mtu: connection.negotiated_mtu,
            data: DataChannel::External(connection.channel),
            control: None,
            control_decoder: Decoder::default(),
            token: Zeroizing::new(vec![]),
            started: now,
            last_control_keepalive: now,
            last_control_read: now,
            last_data_keepalive: now,
        })
    }
    pub fn connect(profile: &Profile, password: &str, otp: Option<&str>) -> Result<Self> {
        Self::connect_with_challenge(profile, password, |_method| {
            otp.filter(|value| !value.is_empty())
                .map(|value| Zeroizing::new(value.to_owned()))
                .ok_or_else(|| AuthError::ChallengeRequired.into())
        })
    }

    /// The callback is invoked only after this live, verified control channel
    /// asks for secondary authentication. It may wait for the user's OTP input.
    pub fn connect_with_challenge<F>(
        profile: &Profile,
        password: &str,
        request_otp: F,
    ) -> Result<Self>
    where
        F: FnMut(&str) -> Result<Zeroizing<String>>,
    {
        Self::connect_with_callbacks(profile, password, request_otp, |_| {})
    }

    /// Reports per-connection transport negotiation without changing the profile.
    /// Status strings contain no credentials, cookies or session identifiers.
    pub fn connect_with_callbacks<F, S>(
        profile: &Profile,
        password: &str,
        mut request_otp: F,
        mut status: S,
    ) -> Result<Self>
    where
        F: FnMut(&str) -> Result<Zeroizing<String>>,
        S: FnMut(&str),
    {
        profile.validate()?;
        if profile.protocol == VpnProtocol::Cisco {
            return Self::from_backend(crate::cisco::connect(profile, password, request_otp)?);
        }
        if profile.protocol == VpnProtocol::OpenVpn {
            return Self::from_backend(crate::openvpn::connect(profile, password, request_otp)?);
        }
        ensure!(
            !profile.username.is_empty() && !profile.username.contains('\0'),
            "Enter a valid username"
        );
        ensure!(
            !password.is_empty() && password.len() <= 1024 && !password.contains('\0'),
            "Enter a valid password (maximum 1024 bytes)"
        );
        let domain = &profile.host;
        let mut control = crypto::connect(profile)?;
        control
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(15)))?;
        control
            .get_ref()
            .set_write_timeout(Some(Duration::from_secs(15)))?;
        control
            .write_all(&first_connect(domain)?)
            .context("Sending Huawei FirstConnect")?;
        if let FirstReply::Legacy(metadata) =
            receive_first(&mut control).context("Receiving Huawei FirstConnect")?
        {
            status("Huawei legacy protocol detected");
            ensure!(
                metadata[..4] == [0; 4],
                "Legacy gateway requires an unsupported certificate authentication method"
            );
            // Legacy FirstConnect is a separate discovery connection. The vendor
            // opens a fresh TLS connection for HTTP authentication; a gateway may
            // reset the discovery socket when HTTP is written to it.
            let discovered_certificate = control
                .ssl()
                .peer_certificate()
                .context("Discovery peer did not send a certificate")?
                .to_der()?;
            drop(control);
            let mut authentication = crypto::connect(profile)?;
            ensure!(
                authentication
                    .ssl()
                    .peer_certificate()
                    .context("Authentication peer did not send a certificate")?
                    .to_der()?
                    == discovered_certificate,
                "Gateway identity changed between discovery and authentication"
            );
            authentication
                .get_ref()
                .set_read_timeout(Some(Duration::from_secs(15)))?;
            authentication
                .get_ref()
                .set_write_timeout(Some(Duration::from_secs(15)))?;
            let auth = crate::legacy_native::authenticate_on(
                profile,
                &mut authentication,
                password,
                request_otp,
            )?;
            return legacy::connect(profile, authentication, auth, &mut status);
        }
        let mut control_decoder = Decoder::default();
        let mut auth = Zeroizing::new(vec![0u8; 260]);
        auth[..domain.len()].copy_from_slice(domain.as_bytes());
        append_tlv(&mut auth, 1, &escaped(&profile.username))?;
        append_tlv(&mut auth, 2, &escaped(password))?;
        let mut mac_bytes = Sha256::digest(format!("{}|{}", profile.username, profile.host));
        mac_bytes[0] = (mac_bytes[0] | 2) & 0xfe;
        let mac = hex::encode_upper(&mac_bytes[..6]);
        let mac = format!("{}-{}-{}", &mac[..4], &mac[4..8], &mac[8..]);
        append_tlv(&mut auth, 3, mac.as_bytes())?;
        write_frame(&mut control, 0x01, &auth)?;
        auth.zeroize();
        let mut token = None;
        let mut secondary_sent = false;
        loop {
            let reply = receive(&mut control, &mut control_decoder, 0x01)?;
            ensure!(
                reply.payload.len() >= 8,
                "Truncated authentication response"
            );
            let status = u32::from_be_bytes(reply.payload[..4].try_into()?);
            let mut method = None;
            let mut token_seen = false;
            for (kind, value) in tlvs(&reply.payload[8..])? {
                match kind {
                    2 => {
                        ensure!(
                            method.is_none() && value.len() == 1,
                            "Malformed secondary authentication method"
                        );
                        method = Some(value[0]);
                    }
                    3 => {
                        ensure!(
                            !token_seen && value.len() >= 32,
                            "Invalid gateway session token"
                        );
                        token = Some(Zeroizing::new(value[..32].to_vec()));
                        token_seen = true;
                    }
                    _ => {}
                }
            }
            if status == 0 {
                break;
            }
            if secondary_sent {
                bail!("Gateway rejected temporary password (status {status})");
            }
            if status != 1 {
                return Err(AuthError::Rejected(status).into());
            }
            let method =
                method.context("Gateway requested secondary authentication without a method")?;
            if method != 1 {
                return Err(AuthError::UnsupportedMethod(method).into());
            }
            let otp = request_otp("sms")?;
            // Vendor SMS v1: command 02, type byte 01, 32-byte NUL-padded value.
            // It receives an ordinary command 01 authentication result, on the
            // same control channel. Never concatenate or replay primary secrets.
            write_frame(&mut control, 0x02, &sms_payload(&otp)?)?;
            secondary_sent = true;
        }
        let token = token.context("Gateway did not provide a session token")?;
        write_frame(&mut control, 0x03, &token)?;
        let reply = receive(&mut control, &mut control_decoder, 0x03)?;
        ensure!(
            reply.payload.len() >= 4 && reply.payload[0] == 0,
            "Gateway rejected IPv4 address allocation"
        );
        let mut vip = None;
        let mut routes = Vec::new();
        let mut dns = Vec::new();
        let mut udp_key = None;
        let mut udp_port = None;
        for (kind, value) in tlvs(&reply.payload[4..])? {
            match kind {
                1 => {
                    ensure!(
                        vip.is_none() && value.len() == 5 && value[4] <= 32,
                        "Invalid assigned IPv4 address"
                    );
                    vip = Some(Ipv4Addr::new(value[0], value[1], value[2], value[3]));
                }
                6 => {
                    ensure!(value.len() % 5 == 0, "Invalid gateway IPv4 routes");
                    for item in value.chunks_exact(5) {
                        let ip = Ipv4Addr::new(item[0], item[1], item[2], item[3]);
                        let prefix = item[4];
                        ensure!(prefix <= 32, "Invalid gateway route prefix");
                        let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
                        ensure!(u32::from(ip) & !mask == 0, "Noncanonical gateway route");
                        let route = format!("{ip}/{prefix}");
                        if !routes.contains(&route) {
                            routes.push(route);
                        }
                    }
                }
                4 => {
                    ensure!(value.len() == 140, "Invalid gateway DNS configuration");
                    for address in value[128..].chunks_exact(4) {
                        let address = Ipv4Addr::new(address[0], address[1], address[2], address[3]);
                        if !address.is_unspecified()
                            && !address.is_broadcast()
                            && !dns.contains(&address)
                        {
                            dns.push(address);
                        }
                    }
                }
                8 => {
                    ensure!(
                        udp_key.is_none() && value.len() == 32,
                        "Invalid negotiated UDP key"
                    );
                    udp_key = Some(Zeroizing::new(value.to_vec()));
                }
                9 => {
                    ensure!(
                        udp_port.is_none() && value.len() == 2,
                        "Invalid negotiated UDP port"
                    );
                    udp_port = Some(u16::from_be_bytes([value[0], value[1]]));
                }
                _ => {}
            }
        }
        let vip = vip.context("Gateway did not assign an IPv4 address")?;
        ensure!(
            !vip.is_unspecified()
                && !vip.is_multicast()
                && !vip.is_broadcast()
                && !vip.is_loopback(),
            "Gateway assigned unusable IPv4 address"
        );
        let mut selected_udp = None;
        let mut udp_was_selected = false;
        if profile.transport != TransportMode::Tls && profile.crypto != CryptoMode::GmTls13 {
            let negotiated = udp_key.zip(udp_port).filter(|(_, port)| *port != 0);
            if let Some((key, port)) = negotiated {
                switch_transport(&mut control, &mut control_decoder, &token, 2)?;
                udp_was_selected = true;
                let mut peer = control.get_ref().peer_addr()?;
                peer.set_port(port);
                let attempt = udp::UdpChannel::connect(peer, vip, key).and_then(|mut channel| {
                    channel.probe()?;
                    Ok(channel)
                });
                match attempt {
                    Ok(channel) => selected_udp = Some(channel),
                    Err(error) if profile.transport == TransportMode::Udp => {
                        return Err(error)
                            .context("Requested UDP fast mode could not be established");
                    }
                    Err(_) => {} // Auto may fall back only after UDP negotiation/probe failure.
                }
            } else if profile.transport == TransportMode::Udp {
                bail!("Gateway did not negotiate an AES-256-GCM UDP key and port");
            }
        }
        let cipher;
        let transport;
        let data = if let Some(channel) = selected_udp {
            cipher = "AES-256-GCM (Huawei NEM v1 over UDP)".to_owned();
            transport = "UDP/AES-256-GCM".to_owned();
            DataChannel::Udp(channel)
        } else {
            if udp_was_selected {
                switch_transport(&mut control, &mut control_decoder, &token, 1)?;
            }
            let mut data = crypto::connect(profile)?;
            // Enforce the same peer identity on both live channels even with a broad CA store.
            let control_cert = control
                .ssl()
                .peer_certificate()
                .context("Missing control TLS certificate")?
                .to_der()?;
            let data_cert = data
                .ssl()
                .peer_certificate()
                .context("Missing data TLS certificate")?
                .to_der()?;
            ensure!(
                control_cert == data_cert,
                "Control and data TLS peer identities differ"
            );
            data.get_ref()
                .set_read_timeout(Some(Duration::from_secs(15)))?;
            data.get_ref()
                .set_write_timeout(Some(Duration::from_secs(5)))?;
            let mut data_decoder = Decoder::default();
            write_frame(&mut data, 0x64, &token)?;
            let reply = receive(&mut data, &mut data_decoder, 0x64)?;
            ensure!(
                reply.payload.as_slice() == [0],
                "Gateway rejected data channel"
            );
            cipher = data
                .ssl()
                .current_cipher()
                .map(|c| format!("{} {}", data.ssl().version_str(), c.name()))
                .unwrap_or_default();
            data.get_ref()
                .set_read_timeout(Some(Duration::from_millis(1)))?;
            transport = "TLS/TCP".to_owned();
            DataChannel::Tls {
                stream: data,
                decoder: data_decoder,
            }
        };
        control
            .get_ref()
            .set_read_timeout(Some(Duration::from_millis(1)))?;
        control
            .get_ref()
            .set_write_timeout(Some(Duration::from_secs(5)))?;
        let now = Instant::now();
        Ok(Self {
            vip,
            routes,
            dns,
            cipher,
            transport,
            negotiated_mtu: None,
            data,
            control: Some(control),
            control_decoder,
            token,
            started: now,
            last_control_keepalive: now,
            last_control_read: now,
            last_data_keepalive: now,
        })
    }

    /// Discovery without authentication; no username/password or route changes.
    pub fn probe(profile: &Profile) -> Result<String> {
        ensure!(
            profile.protocol == VpnProtocol::Huawei,
            "NEM discovery is only available for Huawei gateways"
        );
        let mut stream = crypto::connect(profile)?;
        stream
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(10)))?;
        stream
            .get_ref()
            .set_write_timeout(Some(Duration::from_secs(10)))?;
        stream.write_all(&first_connect(&profile.host)?)?;
        let protocol = match receive_first(&mut stream)? {
            FirstReply::V1 => "Huawei NEM v1".to_owned(),
            FirstReply::Legacy(metadata) => format!(
                "Huawei legacy NEM (16-byte framing; auth method {})",
                u32::from_be_bytes(metadata[..4].try_into()?)
            ),
        };
        Ok(format!(
            "{protocol}; {} {}",
            stream.ssl().version_str(),
            stream
                .ssl()
                .current_cipher()
                .map(|c| c.name())
                .unwrap_or("unknown")
        ))
    }
    /// Apply the local-source prefilter only to the active legacy CHIV channel.
    /// Leave source-policy enforcement for every other backend unchanged.
    pub(crate) fn requires_assigned_ipv4_source(&self) -> bool {
        matches!(&self.data, DataChannel::Legacy(channel) if channel.uses_udp())
    }
    pub fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        ensure!(
            valid_ipv4(packet),
            "TUN supplied malformed or unsupported IPv4 packet"
        );
        let mut payload = Vec::with_capacity(packet.len() + 8);
        payload.extend_from_slice(&[0; 8]);
        payload.extend_from_slice(packet);
        match &mut self.data {
            DataChannel::Tls { stream, .. } => write_frame(stream, 0x66, &payload),
            DataChannel::Udp(channel) => channel.send(0x66, packet),
            DataChannel::Legacy(channel) => channel.send_packet(packet),
            DataChannel::External(channel) => channel.send_packet(packet),
        }
    }
    /// Worker may use a longer idle budget and a short budget after outgoing
    /// bursts, while retaining a bound on cancellation latency.
    pub fn set_read_budget(&self, budget: Duration) -> Result<()> {
        ensure!(
            !budget.is_zero() && budget <= Duration::from_secs(1),
            "Read budget must be within (0, 1s]"
        );
        match &self.data {
            DataChannel::Tls { stream, .. } => stream.get_ref().set_read_timeout(Some(budget))?,
            DataChannel::Udp(channel) => channel.set_read_budget(budget)?,
            DataChannel::Legacy(channel) => channel.set_read_budget(budget)?,
            DataChannel::External(channel) => channel.set_read_budget(budget)?,
        }
        Ok(())
    }
    /// Returns None on a bounded read timeout or a non-data keepalive frame.
    pub fn read_packet(&mut self) -> Result<Option<Vec<u8>>> {
        let (frame, ip_offset) = match &mut self.data {
            DataChannel::Tls { stream, decoder } => (decoder.read(stream)?, 8),
            DataChannel::Udp(channel) => (channel.read()?, 0),
            DataChannel::Legacy(channel) => return channel.read_packet(),
            DataChannel::External(channel) => return channel.read_packet(),
        };
        let Some(frame) = frame else {
            return Ok(None);
        };
        match frame.command {
            0x65 => Ok(None),
            0x08 => {
                if let DataChannel::Udp(channel) = &mut self.data {
                    channel.last_ack = Instant::now();
                }
                Ok(None)
            }
            0x66 => {
                ensure!(
                    frame.payload.len() >= ip_offset && valid_ipv4(&frame.payload[ip_offset..]),
                    "Gateway sent malformed IPv4 packet"
                );
                if let DataChannel::Udp(channel) = &mut self.data {
                    channel.last_ack = Instant::now();
                }
                Ok(Some(frame.payload[ip_offset..].to_vec()))
            }
            cmd => bail!("Unsupported gateway data command 0x{cmd:02x}; reconnect may be required"),
        }
    }
    pub fn keepalive(&mut self) -> Result<()> {
        if let DataChannel::External(channel) = &mut self.data {
            return channel.keepalive();
        }
        if let DataChannel::Legacy(channel) = &mut self.data {
            return channel.keepalive();
        }
        let control = self
            .control
            .as_mut()
            .context("Missing VPN control channel")?;
        if self.last_control_keepalive.elapsed() >= Duration::from_secs(10) {
            let mut payload = Zeroizing::new(self.token.to_vec());
            payload.extend_from_slice(&(self.started.elapsed().as_millis() as u32).to_be_bytes());
            write_frame(control, 0x06, &payload)?;
            self.last_control_keepalive = Instant::now();
        }
        if self.last_data_keepalive.elapsed() >= Duration::from_secs(15) {
            match &mut self.data {
                DataChannel::Tls { stream, .. } => write_frame(stream, 0x65, &[])?,
                DataChannel::Udp(channel) => {
                    ensure!(
                        channel.last_ack.elapsed() < Duration::from_secs(60),
                        "UDP gateway liveness timed out"
                    );
                    channel.send(0x07, &[])?;
                }
                DataChannel::Legacy(_) | DataChannel::External(_) => unreachable!(),
            }
            self.last_data_keepalive = Instant::now();
        }
        // Avoid a timed control read for every data packet. A half-second
        // cadence bounds control-EOF detection without throttling data traffic.
        if self.last_control_read.elapsed() >= Duration::from_millis(500) {
            self.last_control_read = Instant::now();
            // Keep this bounded even if a peer floods the control channel.
            for _ in 0..8 {
                let Some(frame) = self.control_decoder.read(control)? else {
                    break;
                };
                ensure!(
                    frame.command == 0x06,
                    "Gateway control event 0x{:02x} requires unsupported session negotiation",
                    frame.command
                );
            }
        }
        Ok(())
    }
    /// Actual connected peers, used to exclude the outer tunnel from VPN routes.
    pub fn outer_ipv4_addresses(&self) -> Result<Vec<Ipv4Addr>> {
        let mut ips = Vec::new();
        let mut addresses = Vec::new();
        match &self.data {
            DataChannel::Tls { stream, .. } => addresses.push(stream.get_ref().peer_addr()?),
            DataChannel::Udp(channel) => addresses.push(channel.peer_addr()?),
            DataChannel::Legacy(channel) => ips.extend(channel.outer_ipv4_addresses()?),
            DataChannel::External(channel) => ips.extend(channel.outer_ipv4_addresses()?),
        }
        if let Some(control) = &self.control {
            addresses.push(control.get_ref().peer_addr()?);
        }
        ips.extend(addresses.into_iter().filter_map(|peer| match peer.ip() {
            std::net::IpAddr::V4(ip) => Some(ip),
            _ => None,
        }));
        ips.sort_unstable();
        ips.dedup();
        Ok(ips)
    }
    pub fn disconnect(&mut self) {
        if let DataChannel::External(channel) = &mut self.data {
            channel.disconnect();
        }
        if let DataChannel::Legacy(channel) = &mut self.data {
            channel.disconnect();
        }
        self.close_channels();
    }
    fn close_channels(&mut self) {
        if let DataChannel::External(channel) = &mut self.data {
            channel.close();
        }
        if let DataChannel::Tls { stream, .. } = &mut self.data {
            let _ = stream.get_ref().shutdown(std::net::Shutdown::Both);
        }
        if let DataChannel::Legacy(channel) = &mut self.data {
            channel.close_channels();
        }
        if let Some(control) = &self.control {
            let _ = control.get_ref().shutdown(std::net::Shutdown::Both);
        }
        self.token.zeroize();
    }
}
impl Drop for Gateway {
    fn drop(&mut self) {
        // Drop only closes sockets and erases tokens. Explicit disconnect owns
        // the bounded legacy HTTP logout; destructors never start network I/O.
        self.close_channels();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    struct Fragmented {
        chunks: VecDeque<io::Result<Vec<u8>>>,
    }
    impl Read for Fragmented {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let Some(chunk) = self.chunks.pop_front() else {
                return Ok(0);
            };
            let chunk = chunk?;
            let count = out.len().min(chunk.len());
            out[..count].copy_from_slice(&chunk[..count]);
            if count < chunk.len() {
                self.chunks.push_front(Ok(chunk[count..].to_vec()));
            }
            Ok(count)
        }
    }
    #[test]
    fn partial_frame_survives_read_timeout() {
        let mut bytes = Vec::new();
        write_frame(&mut bytes, 0x66, b"hello").unwrap();
        let mut source = Fragmented {
            chunks: VecDeque::from([
                Ok(bytes[..9].to_vec()),
                Err(io::ErrorKind::TimedOut.into()),
                Ok(bytes[9..].to_vec()),
            ]),
        };
        let mut decoder = Decoder::default();
        assert!(decoder.read(&mut source).unwrap().is_none());
        let result = decoder.read(&mut source).unwrap().unwrap();
        assert_eq!(result.command, 0x66);
        assert_eq!(result.payload.as_slice(), b"hello");
    }
    #[test]
    fn rejects_malformed_header_and_tlv() {
        let mut bytes = [0; 8];
        assert!(Decoder::default().read(&mut &bytes[..]).is_err());
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4] = 2;
        assert!(Decoder::default().read(&mut &bytes[..]).is_err());
        assert!(tlvs(&[0, 1, 0, 3, 1]).is_err());
        assert!(tlvs(&[0]).is_err());
    }
    #[test]
    fn first_connect_and_credential_escaping() {
        let first = first_connect("vpn.example").unwrap();
        assert_eq!(first.len(), 340);
        #[cfg(target_os = "macos")]
        assert_eq!(&first[16..22], b"Mac64\0");
        assert_eq!(&first[80..91], b"vpn.example");
        assert_eq!(escaped("a%&+b").as_slice(), b"a%25%26%2Bb\0");
        assert!(first_connect(&"x".repeat(257)).is_err());
    }
    #[test]
    fn ipv4_bounds_are_enforced() {
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[3] = 20;
        assert!(valid_ipv4(&ip));
        ip[3] = 21;
        assert!(!valid_ipv4(&ip));
        ip[3] = 20;
        ip[0] = 0x4f;
        assert!(!valid_ipv4(&ip));
    }

    #[test]
    fn temporary_password_uses_separate_fixed_field() {
        let payload = sms_payload("123456").unwrap();
        assert_eq!(payload.len(), 33);
        assert_eq!(&payload[..7], b"\x01123456");
        assert!(payload[7..].iter().all(|b| *b == 0));
        assert!(sms_payload("").is_err());
        assert!(sms_payload(&"1".repeat(32)).is_err());
        assert!(sms_payload("bad\0value").is_err());
    }
}
