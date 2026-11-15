//! Automatically negotiated legacy CHIV UDP compatibility.
//! AES-128-CBC has no packet authentication in this vendor format. Connected
//! source filtering and recent-IV rejection do not provide cryptographic integrity.
use super::MAGIC;
use anyhow::{Context, Result, ensure};
use openssl::{
    rand::rand_bytes,
    symm::{Cipher, Crypter, Mode},
};
use std::{
    collections::{HashSet, VecDeque},
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const CHIV_HEADER: usize = 28;
const IP_HEADER: usize = 20;
const RECENT_IVS: usize = 8192;
const MAX_IP: usize = 16384;

pub(super) enum Datagram {
    Packet(Vec<u8>),
    Ack,
}
pub(super) struct LegacyUdp {
    socket: UdpSocket,
    key: Zeroizing<[u8; 16]>,
    user_id: u32,
    vip: Ipv4Addr,
    recent: HashSet<[u8; 16]>,
    order: VecDeque<[u8; 16]>,
    pub last_reply: Instant,
    last_probe: Instant,
    probe_received: usize,
    last_probe_shape: String,
    probing: bool,
}
fn cbc(key: &[u8; 16], iv: &[u8; 16], input: &[u8], mode: Mode) -> Result<Zeroizing<Vec<u8>>> {
    ensure!(
        !input.is_empty() && input.len().is_multiple_of(16),
        "Invalid legacy CBC block length"
    );
    let mut cipher = Crypter::new(Cipher::aes_128_cbc(), mode, key, Some(iv))?;
    cipher.pad(false);
    let mut output = Zeroizing::new(vec![0; input.len() + 16]);
    let n = cipher.update(input, &mut output)?;
    let n = n + cipher.finalize(&mut output[n..])?;
    output.truncate(n);
    Ok(output)
}
fn probe_packet(vip: Ipv4Addr, peer: Ipv4Addr) -> Vec<u8> {
    let mut packet = vec![0; 36];
    packet[..10].copy_from_slice(&[0x45, 0x80, 0, 36, 0x12, 0x34, 0, 0, 0x80, 0x11]);
    packet[12..16].copy_from_slice(&vip.octets());
    // The native CHIV probe swaps the result of inet_addr() a second time.
    // Match this synthetic-header quirk only; real IP packets stay unchanged.
    let mut destination = peer.octets();
    destination.reverse();
    packet[16..20].copy_from_slice(&destination);
    packet[20..28].copy_from_slice(&MAGIC);
    packet[32..34].copy_from_slice(&14u16.to_be_bytes());
    packet
}
impl LegacyUdp {
    pub fn new(
        peer: SocketAddr,
        vip: Ipv4Addr,
        user_id: u32,
        key: Zeroizing<[u8; 16]>,
    ) -> Result<Self> {
        ensure!(
            peer.is_ipv4() && peer.port() != 0,
            "Legacy UDP requires an IPv4 gateway and negotiated port"
        );
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(peer)?;
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        let now = Instant::now();
        Ok(Self {
            socket,
            key,
            user_id,
            vip,
            recent: HashSet::new(),
            order: VecDeque::new(),
            last_reply: now,
            last_probe: now,
            probe_received: 0,
            last_probe_shape: "none".into(),
            probing: false,
        })
    }
    fn remember(&mut self, iv: [u8; 16]) {
        self.recent.insert(iv);
        self.order.push_back(iv);
        if self.order.len() > RECENT_IVS
            && let Some(old) = self.order.pop_front()
        {
            self.recent.remove(&old);
        }
    }
    fn encode(&mut self, packet: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            super::valid_ipv4(packet) && packet.len() > IP_HEADER && packet.len() < MAX_IP,
            "Invalid legacy UDP IPv4 packet"
        );
        let mut iv = [0; 16];
        loop {
            rand_bytes(&mut iv)?;
            iv[..4].copy_from_slice(&self.user_id.to_be_bytes());
            if !self.recent.contains(&iv) {
                break;
            }
        }
        let mut body = Zeroizing::new(packet[IP_HEADER..].to_vec());
        let padded_length = body.len().div_ceil(16) * 16;
        body.resize(padded_length, 0);
        let encrypted = cbc(&self.key, &iv, &body, Mode::Encrypt)?;
        let mut out = Vec::with_capacity(CHIV_HEADER + IP_HEADER + encrypted.len());
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&[2, 28, 0, 16]);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&packet[..IP_HEADER]);
        out.extend_from_slice(&encrypted);
        self.remember(iv);
        Ok(out)
    }
    fn decode(&mut self, bytes: &[u8]) -> Result<Option<Datagram>> {
        if bytes.len() < CHIV_HEADER + IP_HEADER + 16
            || bytes.len() > CHIV_HEADER + MAX_IP + 16
            || bytes[..8] != MAGIC
            || bytes[8] != 1
            || bytes[9] != 28
            || bytes[11] != 16
        {
            return Ok(None);
        }
        let iv: [u8; 16] = bytes[12..28].try_into()?;
        // The gateway uses direction1 and its own random IV. The outbound
        // direction2 UID prefix is a routing hint, not an inbound identity.
        if self.recent.contains(&iv) {
            return Ok(None);
        }
        let ip = &bytes[CHIV_HEADER..CHIV_HEADER + IP_HEADER];
        let length = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        let encrypted = &bytes[CHIV_HEADER + IP_HEADER..];
        if ip[0] >> 4 != 4
            || length <= IP_HEADER
            || length >= MAX_IP
            || encrypted.len() != (length - IP_HEADER).div_ceil(16) * 16
        {
            return Ok(None);
        }
        let plain = cbc(&self.key, &iv, encrypted, Mode::Decrypt)?;
        let plain = &plain[..length - IP_HEADER];
        // Probe acknowledgment is NEM inside a synthetic clear IPv4 header.
        let decoded = if plain.len() == 16 && plain[..8] == MAGIC && plain[12..16] == [0, 15, 0, 0]
        {
            Datagram::Ack
        } else {
            // Synthetic probe ACK addresses are opaque vendor metadata. Real
            // tunneled IP packets must still target our assigned address.
            if ip[16..20] != self.vip.octets() {
                return Ok(None);
            }
            let mut packet = Vec::with_capacity(length);
            packet.extend_from_slice(ip);
            packet.extend_from_slice(plain);
            if !super::valid_ipv4(&packet) {
                return Ok(None);
            }
            Datagram::Packet(packet)
        };
        self.remember(iv);
        self.last_reply = Instant::now();
        Ok(Some(decoded))
    }
    pub fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        ensure!(
            packet.get(12..16) == Some(self.vip.octets().as_slice()),
            "Legacy UDP source differs from assigned IPv4"
        );
        let bytes = self.encode(packet)?;
        ensure!(
            self.socket.send(&bytes)? == bytes.len(),
            "Incomplete legacy UDP write"
        );
        Ok(())
    }
    pub fn probe(&mut self) -> Result<()> {
        let peer = match self.socket.peer_addr()?.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => anyhow::bail!("Legacy UDP requires an IPv4 gateway"),
        };
        let packet = probe_packet(self.vip, peer);
        let bytes = self.encode(&packet)?;
        ensure!(
            self.socket.send(&bytes)? == bytes.len(),
            "Incomplete legacy UDP probe"
        );
        self.last_probe = Instant::now();
        Ok(())
    }
    pub fn receive(&mut self) -> Result<Option<Datagram>> {
        let mut bytes = [0; CHIV_HEADER + MAX_IP + 16];
        match self.socket.recv(&mut bytes) {
            Ok(n) => {
                if self.probing {
                    self.probe_received += 1;
                    // Shape/equality metadata only; never expose an IV, identifier,
                    // key, address or decrypted data in negotiation diagnostics.
                    self.last_probe_shape = format!(
                        "length {n}, magic {}, header {:?}, IV user matches {}, destination matches {}, reversed destination matches {}, decrypted NEM ACK {}",
                        n >= 8 && bytes[..8] == MAGIC,
                        if n >= 12 && bytes[..8] == MAGIC {
                            &bytes[8..12]
                        } else {
                            &[]
                        },
                        n >= 16 && bytes[12..16] == self.user_id.to_be_bytes(),
                        n >= 48 && bytes[44..48] == self.vip.octets(),
                        n >= 48
                            && bytes[44..48].iter().copied().eq(self
                                .vip
                                .octets()
                                .into_iter()
                                .rev()),
                        if n == 64 {
                            let iv = bytes[12..28].try_into()?;
                            let plain = cbc(&self.key, iv, &bytes[48..64], Mode::Decrypt)?;
                            plain[..8] == MAGIC && plain[12..16] == [0, 15, 0, 0]
                        } else {
                            false
                        },
                    );
                }
                self.decode(&bytes[..n])
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(e).context("Receiving legacy CBC UDP data"),
        }
    }
    pub fn establish(&mut self) -> Result<()> {
        self.probe_received = 0;
        self.probing = true;
        self.probe()?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if let Some(Datagram::Ack) = self.receive()? {
                self.probing = false;
                return Ok(());
            }
        }
        anyhow::bail!(
            "Legacy CHIV UDP probe timed out; received {} datagrams; last shape: {}; select TLS transport",
            self.probe_received,
            self.last_probe_shape,
        )
    }
    pub fn keepalive(&mut self) -> Result<()> {
        ensure!(
            self.last_reply.elapsed() < Duration::from_secs(60),
            "Legacy UDP peer stopped responding"
        );
        if self.last_probe.elapsed() >= Duration::from_secs(15) {
            self.probe()?;
        }
        Ok(())
    }
    pub fn set_read_budget(&self, budget: Duration) -> Result<()> {
        self.socket.set_read_timeout(Some(budget))?;
        Ok(())
    }
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.peer_addr()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chiv_probe_preserves_native_synthetic_header_byte_order() {
        let packet = probe_packet(Ipv4Addr::new(10, 1, 2, 3), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(&packet[12..20], &[10, 1, 2, 3, 1, 2, 0, 192]);
        assert_eq!(&packet[20..28], &MAGIC);
        assert_eq!(&packet[28..36], &[0, 0, 0, 0, 0, 14, 0, 0]);
        assert!(super::super::valid_ipv4(&packet));
    }
    #[test]
    fn cbc_matches_nist_sp800_38a_vector() {
        let key: [u8; 16] = hex::decode("2b7e151628aed2a6abf7158809cf4f3c")
            .unwrap()
            .try_into()
            .unwrap();
        let iv: [u8; 16] = hex::decode("000102030405060708090a0b0c0d0e0f")
            .unwrap()
            .try_into()
            .unwrap();
        let plain = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let expected = hex::decode("7649abac8119b246cee98e9b12e9197d").unwrap();
        let ciphertext = cbc(&key, &iv, &plain, Mode::Encrypt).unwrap();
        assert_eq!(&*ciphertext, &expected);
        assert_eq!(
            &*cbc(&key, &iv, &ciphertext, Mode::Decrypt).unwrap(),
            &plain
        );
    }
    #[test]
    fn chiv_checks_lengths_replay_and_reflection() {
        let vip = Ipv4Addr::new(10, 0, 0, 2);
        let mut sender = LegacyUdp::new(
            "127.0.0.1:12345".parse().unwrap(),
            vip,
            99,
            Zeroizing::new([3; 16]),
        )
        .unwrap();
        let mut receiver = LegacyUdp::new(
            "127.0.0.1:12345".parse().unwrap(),
            vip,
            12,
            Zeroizing::new([3; 16]),
        )
        .unwrap();
        let mut packet = vec![0; 31];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&31u16.to_be_bytes());
        packet[16..20].copy_from_slice(&vip.octets());
        packet[20..].copy_from_slice(b"hello world");
        let mut bytes = sender.encode(&packet).unwrap();
        assert!(receiver.decode(&bytes).unwrap().is_none());
        bytes[8] = 1; // Observed gateway-to-client direction.
        bytes[10] = 190; // The native envelope leaves this opaque byte unspecified.
        assert!(sender.decode(&bytes).unwrap().is_none());
        assert!(
            receiver
                .decode(&bytes[..bytes.len() - 1])
                .unwrap()
                .is_none()
        );
        assert!(
            matches!(receiver.decode(&bytes).unwrap(), Some(Datagram::Packet(p)) if p == packet)
        );
        assert!(receiver.decode(&bytes).unwrap().is_none());
    }

    #[test]
    fn gateway_probe_ack_uses_its_own_iv_and_synthetic_addresses() {
        let vip = Ipv4Addr::new(10, 0, 0, 2);
        let mut server = LegacyUdp::new(
            "127.0.0.1:12345".parse().unwrap(),
            vip,
            99,
            Zeroizing::new([3; 16]),
        )
        .unwrap();
        let mut client = LegacyUdp::new(
            "127.0.0.1:12345".parse().unwrap(),
            vip,
            12,
            Zeroizing::new([3; 16]),
        )
        .unwrap();
        let mut packet = probe_packet(vip, Ipv4Addr::new(192, 0, 2, 1));
        packet[32..34].copy_from_slice(&15u16.to_be_bytes());
        let mut datagram = server.encode(&packet).unwrap();
        datagram[8] = 1;
        assert!(matches!(
            client.decode(&datagram).unwrap(),
            Some(Datagram::Ack)
        ));
        assert!(client.decode(&datagram).unwrap().is_none());
    }
}
