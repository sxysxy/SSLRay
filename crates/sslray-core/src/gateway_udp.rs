//! Observed Huawei NEM v1 AES-256-GCM datagrams. No vendor code is linked/copied.
use super::{Frame, MAGIC, write_frame};
use anyhow::{Context, Result, ensure};
use openssl::{
    rand::rand_bytes,
    symm::{Cipher, decrypt_aead, encrypt_aead},
};
use std::{
    collections::{HashSet, VecDeque},
    io,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const HEADER: usize = 52;
const RECENT_NONCES: usize = 8192;

pub(super) struct UdpChannel {
    socket: UdpSocket,
    key: Zeroizing<Vec<u8>>,
    vip: Ipv4Addr,
    // The observed protocol has no sequence number. Reject recent inbound replays
    // and reflected outbound packets using the actual 12-byte GCM nonce.
    nonces: HashSet<[u8; 12]>,
    nonce_order: VecDeque<[u8; 12]>,
    pub last_ack: Instant,
}
impl UdpChannel {
    pub fn connect(peer: SocketAddr, vip: Ipv4Addr, key: Zeroizing<Vec<u8>>) -> Result<Self> {
        ensure!(
            key.len() == 32 && peer.port() != 0,
            "Invalid negotiated UDP key or port"
        );
        let socket = UdpSocket::bind(if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        socket.connect(peer)?;
        socket.set_read_timeout(Some(Duration::from_millis(1)))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        Ok(Self {
            socket,
            key,
            vip,
            nonces: HashSet::new(),
            nonce_order: VecDeque::new(),
            last_ack: Instant::now(),
        })
    }
    fn remember_nonce(&mut self, nonce: [u8; 12]) -> bool {
        if !self.nonces.insert(nonce) {
            return false;
        }
        self.nonce_order.push_back(nonce);
        if self.nonce_order.len() > RECENT_NONCES
            && let Some(old) = self.nonce_order.pop_front()
        {
            self.nonces.remove(&old);
        }
        true
    }
    fn encode(&mut self, command: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let mut plain = Zeroizing::new(Vec::with_capacity(payload.len() + 8));
        write_frame(&mut *plain, command, payload)?;
        ensure!(
            plain.len() + HEADER <= 65507,
            "IPv4 datagram exceeds UDP maximum"
        );
        let mut packet = vec![0u8; HEADER];
        packet[0] = 1;
        packet[1] = 2;
        packet[4..8].copy_from_slice(&self.vip.octets());
        let nonce = loop {
            rand_bytes(&mut packet[20..36])?;
            let nonce = packet[20..32].try_into()?;
            if self.remember_nonce(nonce) {
                break nonce;
            }
        };
        let mut tag = [0; 16];
        let ciphertext = encrypt_aead(
            Cipher::aes_256_gcm(),
            &self.key,
            Some(&nonce),
            &[],
            &plain,
            &mut tag,
        )?;
        packet[36..52].copy_from_slice(&tag);
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }
    fn decode(&mut self, packet: &[u8]) -> Result<Option<Frame>> {
        // Foreign/forged/replayed datagrams do not tear down the authenticated
        // session. The connected UDP socket already filters source IP+port.
        if packet.len() < HEADER + 8
            || packet.len() > 65507
            || packet[..4] != [1, 2, 0, 0]
            || packet[4..8] != self.vip.octets()
        {
            return Ok(None);
        }
        let nonce: [u8; 12] = packet[20..32].try_into()?;
        if self.nonces.contains(&nonce) {
            return Ok(None);
        }
        let plain = match decrypt_aead(
            Cipher::aes_256_gcm(),
            &self.key,
            Some(&nonce),
            &[],
            &packet[HEADER..],
            &packet[36..52],
        ) {
            Ok(p) => Zeroizing::new(p),
            Err(_) => return Ok(None),
        };
        if plain.len() < 8 || plain[..4] != MAGIC || plain[4] != 1 {
            return Ok(None);
        }
        let length = u16::from_be_bytes([plain[6], plain[7]]) as usize;
        if plain.len() != length + 8 {
            return Ok(None);
        }
        self.remember_nonce(nonce);
        Ok(Some(Frame {
            command: plain[5],
            payload: Zeroizing::new(plain[8..].to_vec()),
        }))
    }
    pub fn send(&mut self, command: u8, payload: &[u8]) -> Result<()> {
        let packet = self.encode(command, payload)?;
        ensure!(
            self.socket.send(&packet)? == packet.len(),
            "Incomplete UDP send"
        );
        Ok(())
    }
    pub fn set_read_budget(&self, budget: Duration) -> Result<()> {
        self.socket.set_read_timeout(Some(budget))?;
        Ok(())
    }
    pub fn peer_addr(&self) -> Result<std::net::SocketAddr> {
        Ok(self.socket.peer_addr()?)
    }
    pub fn read(&mut self) -> Result<Option<Frame>> {
        let mut packet = [0; 65536];
        match self.socket.recv(&mut packet) {
            Ok(n) => self.decode(&packet[..n]),
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
            Err(e) => Err(e).context("Reading VPN UDP datagram"),
        }
    }
    pub fn probe(&mut self) -> Result<()> {
        self.send(0x07, &[])?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if let Some(reply) = self.read()?
                && reply.command == 0x08
                && reply.payload.is_empty()
            {
                self.last_ack = Instant::now();
                return Ok(());
            }
        }
        anyhow::bail!("Huawei UDP probe timed out; no authenticated ACK received")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn channel() -> UdpChannel {
        UdpChannel::connect(
            "127.0.0.1:9".parse().unwrap(),
            Ipv4Addr::new(10, 0, 0, 2),
            Zeroizing::new(vec![0xab; 32]),
        )
        .unwrap()
    }
    #[test]
    fn encrypted_datagrams_reject_tampering_replay_and_reflection() {
        let mut sender = channel();
        let mut receiver = channel();
        let packet = sender.encode(0x66, b"test packet").unwrap();
        assert_eq!(packet.len(), HEADER + 8 + 11);
        assert!(!packet.windows(11).any(|bytes| bytes == b"test packet"));
        let mut tampered = packet.clone();
        tampered[HEADER + 1] ^= 1;
        assert!(receiver.decode(&tampered).unwrap().is_none());
        let frame = receiver.decode(&packet).unwrap().unwrap();
        assert_eq!(frame.command, 0x66);
        assert_eq!(frame.payload.as_slice(), b"test packet");
        assert!(receiver.decode(&packet).unwrap().is_none());
        assert!(sender.decode(&packet).unwrap().is_none());
    }
    #[test]
    fn wrong_key_is_rejected() {
        let packet = channel().encode(0x08, &[]).unwrap();
        let mut receiver = channel();
        receiver.key[0] ^= 1;
        assert!(receiver.decode(&packet).unwrap().is_none());
    }
    #[test]
    fn authenticated_loopback_probe() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = server.local_addr().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let worker = std::thread::spawn(move || {
            let mut buffer = [0; 1024];
            let (n, client) = server.recv_from(&mut buffer).unwrap();
            let mut responder = channel();
            assert_eq!(
                responder.decode(&buffer[..n]).unwrap().unwrap().command,
                0x07
            );
            let reply = responder.encode(0x08, &[]).unwrap();
            server.send_to(&reply, client).unwrap();
        });
        let mut client = UdpChannel::connect(
            peer,
            Ipv4Addr::new(10, 0, 0, 2),
            Zeroizing::new(vec![0xab; 32]),
        )
        .unwrap();
        client.probe().unwrap();
        worker.join().unwrap();
    }
}
