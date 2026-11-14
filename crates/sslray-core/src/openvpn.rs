//! Synchronous packet bridge to the native, in-process OpenVPN engine.
//! User files are read before elevation; session credentials never enter a file.
use crate::{
    backend::{BackendConnection, PacketBackend},
    config::{CryptoMode, Profile, RouteMode, VpnProtocol},
    platform::Ipv4Route,
};
use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use bytes::Bytes;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Padding,
    sign::{RsaPssSaltlen, Signer},
    x509::X509,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    net::{Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use vpn_core::{
    Engine, OpenVpnProfile, OpenVpnRemote, PacketIo, Prompt, Prompter, SessionContext,
    SignAlgorithm, Transport, TunnelSettings,
};
use vpn_openvpn::OpenVpnEngine;
use zeroize::{Zeroize, Zeroizing};

pub const PREPARED_PREFIX: &str = "sslray-openvpn-v1:";
pub const MAX_PREPARED: usize = 256 * 1024;
const MAX_FILE: u64 = 128 * 1024;
const QUEUE_PACKETS: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(120);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Serialize, Deserialize)]
struct Prepared {
    engine: OpenVpnProfile,
    private_key: Option<String>,
    routes: Vec<String>,
    pull_routes: bool,
    mtu: Option<u16>,
}
impl Drop for Prepared {
    fn drop(&mut self) {
        if let Some(key) = &mut self.private_key {
            key.zeroize();
        }
    }
}

fn validate_prepared(prepared: &Prepared) -> Result<()> {
    prepared.engine.validate()?;
    ensure!(
        prepared.engine.remote_cert_tls,
        "OpenVPN service-certificate validation cannot be disabled"
    );
    ensure!(
        prepared.engine.client_certificate.is_none()
            && prepared.engine.client_chain_pem.is_none()
            && prepared.engine.client_key_pem.is_none(),
        "Unsupported prepared OpenVPN certificate source"
    );
    ensure!(
        prepared.engine.client_cert_pem.is_some() == prepared.private_key.is_some(),
        "OpenVPN client certificate and private key must be supplied together"
    );
    if let Some(mtu) = prepared.mtu {
        ensure!((576..=1500).contains(&mtu), "Invalid prepared OpenVPN MTU");
    }
    for route in &prepared.routes {
        let _: Ipv4Route = route.parse()?;
    }
    Ok(())
}

/// Read a selected configuration and its adjacent files as the calling user.
/// Return only an in-memory IPC copy; persist the original path-based profile.
/// The caller must erase `openvpn_config` when this prepared copy is discarded.
pub fn prepare(profile: &Profile) -> Result<Profile> {
    if profile.protocol != VpnProtocol::OpenVpn {
        return Ok(profile.clone());
    }
    ensure!(
        profile.crypto == CryptoMode::Standard,
        "This OpenVPN backend does not support GM TLS"
    );
    let prepared = if let Some(json) = profile.openvpn_config.strip_prefix(PREPARED_PREFIX) {
        ensure!(
            profile.openvpn_config.len() <= MAX_PREPARED,
            "OpenVPN configuration exceeds the IPC limit"
        );
        serde_json::from_str::<Prepared>(json).context("Invalid prepared OpenVPN configuration")?
    } else {
        load_profile(profile)?
    };
    validate_prepared(&prepared)?;
    let json = Zeroizing::new(serde_json::to_string(&prepared)?);
    ensure!(
        PREPARED_PREFIX.len() + json.len() <= MAX_PREPARED,
        "OpenVPN configuration and certificates exceed 256 KiB"
    );
    let mut copy = profile.clone();
    copy.openvpn_config = format!("{PREPARED_PREFIX}{}", json.as_str());
    Ok(copy)
}

/// Determine whether to prompt before connecting, while retaining certificate-only
/// OpenVPN profiles that intentionally use no username or password.
pub fn requires_password(profile: &Profile) -> Result<bool> {
    if profile.protocol != VpnProtocol::OpenVpn {
        return Ok(true);
    }
    let prepared = if let Some(json) = profile.openvpn_config.strip_prefix(PREPARED_PREFIX) {
        ensure!(
            profile.openvpn_config.len() <= MAX_PREPARED,
            "OpenVPN configuration exceeds the IPC limit"
        );
        serde_json::from_str::<Prepared>(json).context("Invalid prepared OpenVPN configuration")?
    } else {
        load_profile(profile)?
    };
    validate_prepared(&prepared)?;
    Ok(prepared.engine.auth_user_pass)
}

fn read_file(path: &Path) -> Result<Zeroizing<String>> {
    let file =
        File::open(path).context("Cannot open an OpenVPN configuration or certificate file")?;
    ensure!(
        file.metadata()?.is_file(),
        "OpenVPN configuration inputs must be regular files"
    );
    let mut text = Zeroizing::new(String::new());
    file.take(MAX_FILE + 1)
        .read_to_string(&mut text)
        .context("Cannot read an OpenVPN text file")?;
    ensure!(
        text.len() as u64 <= MAX_FILE,
        "OpenVPN configuration input exceeds 128 KiB"
    );
    Ok(text)
}

fn words(line: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let (mut quote, mut escaped, mut active) = (None, false, false);
    for c in line.chars() {
        if escaped {
            word.push(c);
            escaped = false;
            active = true;
            continue;
        }
        if c == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else {
                word.push(c);
            }
            continue;
        }
        match c {
            '\'' | '"' => {
                quote = Some(c);
                active = true;
            }
            '#' | ';' if !active => break,
            c if c.is_whitespace() => {
                if active {
                    words.push(std::mem::take(&mut word));
                    active = false;
                }
            }
            c => {
                word.push(c);
                active = true;
            }
        }
    }
    ensure!(
        quote.is_none() && !escaped,
        "Unterminated quote or escape in OpenVPN configuration"
    );
    if active {
        words.push(word);
    }
    Ok(words)
}

fn transport(value: &str) -> Result<Transport> {
    match value {
        "udp" | "udp4" => Ok(Transport::Udp),
        "tcp" | "tcp4" | "tcp-client" | "tcp4-client" => Ok(Transport::Tcp),
        _ => bail!("Only IPv4 OpenVPN UDP or TCP client transport is supported"),
    }
}

fn load_profile(profile: &Profile) -> Result<Prepared> {
    let path = Path::new(&profile.openvpn_config)
        .canonicalize()
        .context("Cannot locate the OpenVPN configuration")?;
    let dir = path
        .parent()
        .context("OpenVPN configuration has no parent directory")?;
    let text = read_file(&path)?;
    let mut lines = Vec::new();
    let mut blocks = HashMap::<String, Zeroizing<String>>::new();
    let mut block: Option<(String, Zeroizing<String>)> = None;
    for line in text.lines() {
        let trim = line.trim();
        if let Some((tag, content)) = &mut block {
            if trim == format!("</{tag}>") {
                let (tag, content) = block.take().expect("active block");
                ensure!(
                    blocks.insert(tag, content).is_none(),
                    "Duplicate OpenVPN inline certificate or key"
                );
            } else {
                content.push_str(line);
                content.push('\n');
            }
            continue;
        }
        if trim.starts_with('<') && trim.ends_with('>') {
            let tag = &trim[1..trim.len() - 1];
            ensure!(
                ["ca", "cert", "key", "tls-auth", "tls-crypt"].contains(&tag),
                "Unsupported OpenVPN inline block"
            );
            block = Some((tag.to_owned(), Zeroizing::new(String::new())));
            continue;
        }
        let tokens = words(line)?;
        if !tokens.is_empty() {
            lines.push(tokens);
        }
    }
    ensure!(
        block.is_none(),
        "Unterminated OpenVPN inline certificate or key"
    );
    let mut engine: OpenVpnProfile = serde_json::from_value(serde_json::json!({"remotes":[]}))?;
    let mut proto = Transport::Udp;
    let mut port = 1194u16;
    for line in &lines {
        let arg = |n| line.get(n).map(String::as_str).unwrap_or("");
        match arg(0).trim_start_matches("--") {
            "proto" => proto = transport(arg(1))?,
            "port" | "rport" => port = arg(1).parse().context("Invalid OpenVPN remote port")?,
            _ => {}
        }
    }
    let contents = |name: &str, args: &[String]| -> Result<Option<String>> {
        if let Some(block) = blocks.get(name) {
            return Ok(Some(block.to_string()));
        }
        if let Some(file) = args.first() {
            ensure!(file != "[inline]", "OpenVPN inline block is missing");
            let referenced = dir
                .join(file)
                .canonicalize()
                .context("Cannot locate an OpenVPN certificate or key")?;
            ensure!(
                referenced.starts_with(dir),
                "OpenVPN files must stay inside the configuration's directory"
            );
            return Ok(Some(read_file(&referenced)?.to_string()));
        }
        Ok(None)
    };
    ensure!(
        !(blocks.contains_key("tls-auth") && blocks.contains_key("tls-crypt")),
        "Use only one OpenVPN control-channel key"
    );
    let mut prepared = Prepared {
        engine: engine.clone(),
        private_key: None,
        routes: Vec::new(),
        pull_routes: true,
        mtu: None,
    };
    let mut cipher = None;
    let mut ncp = false;
    for line in &lines {
        let name = line[0].trim_start_matches("--");
        ensure!(
            name.len() <= 64 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "Invalid OpenVPN directive"
        );
        let arg = |n| line.get(n).map(String::as_str).unwrap_or("");
        match name {
            "client"
            | "tls-client"
            | "pull"
            | "nobind"
            | "persist-key"
            | "persist-tun"
            | "resolv-retry"
            | "verb"
            | "mute"
            | "explicit-exit-notify"
            | "auth-nocache"
            | "push-peer-info" => {}
            "dev" => ensure!(
                arg(1).starts_with("tun"),
                "Only OpenVPN dev tun is supported"
            ),
            "dev-type" => ensure!(arg(1) == "tun", "Only OpenVPN dev tun is supported"),
            "proto" | "port" | "rport" => {}
            "remote" => engine.remotes.push(OpenVpnRemote {
                host: arg(1).to_owned(),
                port: if arg(2).is_empty() {
                    port
                } else {
                    arg(2).parse().context("Invalid OpenVPN remote port")?
                },
                transport: if arg(3).is_empty() {
                    proto
                } else {
                    transport(arg(3))?
                },
            }),
            "auth-user-pass" => {
                ensure!(
                    line.len() == 1,
                    "OpenVPN auth-user-pass files are not read; enter credentials in SSLRay"
                );
                engine.auth_user_pass = true;
            }
            "ca" => engine.ca_pem = contents(name, &line[1..])?,
            "cert" => engine.client_cert_pem = contents(name, &line[1..])?,
            "key" => prepared.private_key = contents(name, &line[1..])?,
            "tls-auth" | "tls-crypt" => {
                ensure!(
                    engine.static_key.is_none(),
                    "Use only one OpenVPN control-channel key"
                );
                engine.static_key = contents(name, &line[1..])?;
                engine.control_channel = if name == "tls-auth" {
                    vpn_core::ControlChannel::TlsAuth
                } else {
                    vpn_core::ControlChannel::TlsCrypt
                };
                if name == "tls-auth" && !arg(2).is_empty() {
                    engine.key_direction =
                        Some(arg(2).parse().context("Invalid OpenVPN key direction")?);
                }
            }
            "key-direction" => {
                engine.key_direction =
                    Some(arg(1).parse().context("Invalid OpenVPN key direction")?)
            }
            "auth" => engine.auth_digest = arg(1).to_owned(),
            "data-ciphers" => {
                engine.data_ciphers = arg(1).split(':').map(str::to_owned).collect();
                ncp = true;
            }
            "cipher" | "data-ciphers-fallback" => cipher = Some(arg(1).to_owned()),
            "remote-cert-tls" => ensure!(
                arg(1) == "server",
                "OpenVPN requires remote-cert-tls server"
            ),
            "verify-x509-name" => {
                engine.verify_x509_name = Some(vpn_core::X509NameCheck {
                    name: arg(1).to_owned(),
                    kind: match arg(2) {
                        "" | "subject" => vpn_core::X509NameKind::Subject,
                        "name" => vpn_core::X509NameKind::Name,
                        "name-prefix" => vpn_core::X509NameKind::NamePrefix,
                        _ => bail!("Unsupported OpenVPN certificate name policy"),
                    },
                })
            }
            "peer-fingerprint" => engine.trusted_cert.push(arg(1).to_owned()),
            "static-challenge" => {
                ensure!(
                    matches!(arg(2), "0" | "1"),
                    "OpenVPN static-challenge requires an echo flag of 0 or 1"
                );
                engine.static_challenge = Some(vpn_core::StaticChallenge {
                    text: arg(1).to_owned(),
                    echo: arg(2) == "1",
                })
            }
            "reneg-sec" => {
                engine.reneg_sec = arg(1)
                    .parse()
                    .context("Invalid OpenVPN renegotiation interval")?
            }
            "tls-version-min" => ensure!(
                arg(1) == "1.2",
                "This OpenVPN backend currently requires tls-version-min 1.2"
            ),
            "comp-lzo" => {
                ensure!(arg(1) == "no", "OpenVPN packet compression is unsupported");
                engine.compression = vpn_core::Compression::Lzo;
            }
            "compress" => {
                engine.compression = match arg(1) {
                    "" | "stub" => vpn_core::Compression::Stub,
                    "stub-v2" => vpn_core::Compression::StubV2,
                    _ => bail!("OpenVPN packet compression is unsupported"),
                }
            }
            "route-nopull" => prepared.pull_routes = false,
            "route" => {
                ensure!(
                    line.len() <= 3,
                    "OpenVPN route gateway overrides are unsupported; use SSLRay routing settings"
                );
                let network: Ipv4Addr = arg(1)
                    .parse()
                    .context("OpenVPN routes require an IPv4 network")?;
                let mask: Ipv4Addr = if arg(2).is_empty() {
                    Ipv4Addr::BROADCAST
                } else {
                    arg(2).parse().context("Invalid OpenVPN route mask")?
                };
                let mask = u32::from(mask);
                let prefix = mask.leading_ones();
                ensure!(
                    mask.trailing_zeros() + prefix == 32 && prefix > 0,
                    "Use SSLRay full-tunnel routing for the default route"
                );
                let route: Ipv4Route = format!("{network}/{prefix}").parse()?;
                prepared.routes.push(route.to_string());
            }
            "redirect-gateway" => ensure!(
                profile.route_mode == RouteMode::FullTunnel,
                "Select SSLRay IPv4 full-tunnel routing for redirect-gateway"
            ),
            "tun-mtu" => {
                let mtu: u16 = arg(1).parse().context("Invalid OpenVPN MTU")?;
                ensure!((576..=1500).contains(&mtu), "Invalid OpenVPN MTU");
                prepared.mtu = Some(mtu);
            }
            _ => bail!("Unsupported OpenVPN directive: {name}"),
        }
    }
    for name in ["ca", "cert", "key", "tls-auth", "tls-crypt"] {
        if let Some(block) = blocks.remove(name) {
            match name {
                "ca" => engine.ca_pem = Some(block.to_string()),
                "cert" => engine.client_cert_pem = Some(block.to_string()),
                "key" => prepared.private_key = Some(block.to_string()),
                _ => {
                    let mode = if name == "tls-auth" {
                        vpn_core::ControlChannel::TlsAuth
                    } else {
                        vpn_core::ControlChannel::TlsCrypt
                    };
                    ensure!(
                        engine.static_key.is_none() || engine.control_channel == mode,
                        "Use only one OpenVPN control-channel key"
                    );
                    if engine.static_key.is_none() {
                        engine.static_key = Some(block.to_string());
                        engine.control_channel = mode;
                    }
                }
            }
        }
    }
    if !ncp && let Some(cipher) = cipher {
        engine.data_ciphers = vec![cipher];
    }
    if !profile.username.is_empty() {
        engine.username = Some(profile.username.clone());
    }
    if !profile.certificate_sha256.is_empty() {
        engine.trusted_cert = vec![profile.certificate_sha256.clone()];
    }
    ensure!(
        engine.control_channel != vpn_core::ControlChannel::TlsCrypt
            || engine.key_direction.is_none(),
        "OpenVPN tls-crypt does not accept key-direction"
    );
    ensure!(
        engine.client_cert_pem.is_some() == prepared.private_key.is_some(),
        "OpenVPN client certificate and private key must be supplied together"
    );
    if let Some(key) = &prepared.private_key {
        ensure!(
            !key.contains("ENCRYPTED"),
            "Encrypted OpenVPN private keys are currently unsupported"
        );
    }
    engine.validate()?;
    prepared.engine = engine;
    Ok(prepared)
}

struct Question {
    reply: oneshot::Sender<Result<Zeroizing<String>>>,
}
struct Broker {
    password: Mutex<Option<Zeroizing<String>>>,
    key: Option<PKey<Private>>,
    certificate: Option<String>,
    questions: mpsc::Sender<Question>,
    cancel: CancellationToken,
}
#[async_trait]
impl Prompter for Broker {
    async fn ask(&self, prompt: Prompt) -> Result<Zeroizing<String>> {
        if let Some(request) = prompt.sign {
            ensure!(
                Some(request.certificate.as_str()) == self.certificate.as_deref(),
                "Unknown OpenVPN client signing identity"
            );
            let data = hex::decode(&request.data).context("Invalid OpenVPN signature request")?;
            ensure!(
                vpn_core::prompt::is_tls_client_signature_octets(&data),
                "Refused non-TLS OpenVPN signature request"
            );
            let (digest, pss) = match request.algorithm {
                SignAlgorithm::RsaPkcs1Sha256 | SignAlgorithm::EcdsaSha256 => {
                    (MessageDigest::sha256(), false)
                }
                SignAlgorithm::RsaPkcs1Sha384 | SignAlgorithm::EcdsaSha384 => {
                    (MessageDigest::sha384(), false)
                }
                SignAlgorithm::RsaPkcs1Sha512 => (MessageDigest::sha512(), false),
                SignAlgorithm::RsaPssSha256 => (MessageDigest::sha256(), true),
                SignAlgorithm::RsaPssSha384 => (MessageDigest::sha384(), true),
                SignAlgorithm::RsaPssSha512 => (MessageDigest::sha512(), true),
                SignAlgorithm::RsaPkcs1Sha1 => bail!("RSA SHA-1 client signatures are unsupported"),
            };
            let mut signer = Signer::new(
                digest,
                self.key.as_ref().context("Missing OpenVPN client key")?,
            )?;
            if pss {
                signer.set_rsa_padding(Padding::PKCS1_PSS)?;
                signer.set_rsa_mgf1_md(digest)?;
                signer.set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)?;
            }
            signer.update(&data)?;
            return Ok(Zeroizing::new(hex::encode(signer.sign_to_vec()?)));
        }
        if prompt.key == "password" {
            return self
                .password
                .lock()
                .map_err(|_| anyhow::anyhow!("OpenVPN credential lock failed"))?
                .take()
                .context("OpenVPN password was already consumed");
        }
        ensure!(
            prompt.key == "otp",
            "OpenVPN requires a username in SSLRay settings"
        );
        let (reply, answer) = oneshot::channel();
        tokio::select! {
            _ = self.cancel.cancelled() => bail!("OpenVPN authentication cancelled"),
            sent = self.questions.send(Question { reply }) => sent.context("OpenVPN prompt receiver closed")?,
        }
        tokio::select! {
            _ = self.cancel.cancelled() => bail!("OpenVPN authentication cancelled"),
            answer = answer => answer.context("OpenVPN prompt cancelled")?,
        }
    }
    async fn open_url(&self, _: &str) -> Result<()> {
        bail!("OpenVPN browser authentication is unsupported")
    }
}

struct Connected {
    settings: TunnelSettings,
    peer: SocketAddr,
    cipher: String,
    transport: Transport,
}
struct Channel {
    tx: Option<mpsc::Sender<Bytes>>,
    rx: mpsc::Receiver<Bytes>,
    cancel: CancellationToken,
    worker: Option<JoinHandle<()>>,
    worker_done: std::sync::mpsc::Receiver<()>,
    finished: Arc<Mutex<Option<Result<(), String>>>>,
    budget_us: AtomicU64,
    peer: Ipv4Addr,
}
impl Channel {
    fn status(&self) -> Result<()> {
        let state = self
            .finished
            .lock()
            .map_err(|_| anyhow::anyhow!("OpenVPN state lock failed"))?;
        if let Some(result) = &*state {
            match result {
                Ok(()) => bail!("OpenVPN connection closed"),
                Err(error) => bail!("{error}"),
            }
        }
        Ok(())
    }
    fn stop(&mut self) {
        self.cancel.cancel();
        self.tx.take();
        self.rx.close();
        if let Some(worker) = self.worker.take() {
            // The worker erases engine/key state before stopping Tokio. Never
            // block the caller indefinitely on an OS resolver thread.
            if self.worker_done.recv_timeout(SHUTDOWN_TIMEOUT).is_ok() || worker.is_finished() {
                let _ = worker.join();
            }
        }
    }
}
fn valid_ipv4(packet: &[u8]) -> bool {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return false;
    }
    let header = usize::from(packet[0] & 15) * 4;
    header >= 20
        && header <= packet.len()
        && usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len()
}
impl Drop for Channel {
    fn drop(&mut self) {
        self.stop();
    }
}
impl PacketBackend for Channel {
    fn send_packet(&mut self, packet: &[u8]) -> Result<()> {
        self.status()?;
        let tx = self.tx.as_ref().context("OpenVPN channel closed")?;
        match tx.try_send(Bytes::copy_from_slice(packet)) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => bail!("OpenVPN packet worker closed"),
        }
    }
    fn read_packet(&mut self) -> Result<Option<Vec<u8>>> {
        let deadline =
            Instant::now() + Duration::from_micros(self.budget_us.load(Ordering::Relaxed));
        loop {
            match self.rx.try_recv() {
                Ok(packet) => {
                    ensure!(valid_ipv4(&packet), "OpenVPN delivered malformed IPv4 data");
                    return Ok(Some(packet.to_vec()));
                }
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    self.status()?;
                    bail!("OpenVPN packet worker closed");
                }
                Err(mpsc::error::TryRecvError::Empty) => {
                    self.status()?;
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    thread::sleep(
                        Duration::from_micros(500)
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                }
            }
        }
    }
    fn set_read_budget(&self, budget: Duration) -> Result<()> {
        ensure!(
            !budget.is_zero() && budget <= Duration::from_secs(1),
            "Invalid OpenVPN read budget"
        );
        self.budget_us
            .store(budget.as_micros().max(1) as u64, Ordering::Relaxed);
        Ok(())
    }
    fn keepalive(&mut self) -> Result<()> {
        self.status()
    }
    fn outer_ipv4_addresses(&self) -> Result<Vec<Ipv4Addr>> {
        Ok(vec![self.peer])
    }
    fn disconnect(&mut self) {
        self.stop();
    }
    fn close(&mut self) {
        self.stop();
    }
}

fn safe_failure(error: &anyhow::Error) -> String {
    use vpn_core::FailureKind;
    match vpn_core::failure::kind_of(error) {
        FailureKind::AuthFailed => "OpenVPN authentication failed",
        FailureKind::OtpRejected => "OpenVPN verification code rejected",
        FailureKind::Cancelled => "OpenVPN connection cancelled",
        FailureKind::NeedsUser => "OpenVPN requires a fresh one-time code; reconnect",
        FailureKind::Timeout => "OpenVPN negotiation timed out",
        FailureKind::Unreachable => "OpenVPN server is unreachable",
        _ => "OpenVPN connection failed; check the configuration and server identity",
    }
    .to_owned()
}

pub(crate) fn connect(
    profile: &Profile,
    password: &str,
    mut challenge: impl FnMut(&str) -> Result<Zeroizing<String>>,
) -> Result<BackendConnection> {
    ensure!(
        profile.crypto == CryptoMode::Standard,
        "This OpenVPN backend does not support GM TLS"
    );
    ensure!(
        profile.openvpn_config.len() <= MAX_PREPARED,
        "OpenVPN configuration exceeds the IPC limit"
    );
    let json = profile
        .openvpn_config
        .strip_prefix(PREPARED_PREFIX)
        .context("OpenVPN files must be prepared by the user process before connecting")?;
    let mut prepared: Prepared =
        serde_json::from_str(json).context("Invalid prepared OpenVPN configuration")?;
    validate_prepared(&prepared)?;
    ensure!(
        !prepared.engine.auth_user_pass || (!password.is_empty() && password.len() <= 1024),
        "Enter a valid OpenVPN password"
    );
    ensure!(
        !prepared.engine.auth_user_pass
            || prepared
                .engine
                .username
                .as_ref()
                .is_some_and(|s| !s.is_empty()),
        "Enter the OpenVPN username in SSLRay settings"
    );
    let key = prepared
        .private_key
        .take()
        .map(Zeroizing::new)
        .map(|pem| {
            PKey::private_key_from_pem(pem.as_bytes()).context("Invalid OpenVPN client private key")
        })
        .transpose()?;
    if let Some(key) = &key {
        ensure!(
            key.bits() <= 8192,
            "OpenVPN client keys over 8192 bits are unsupported"
        );
    }
    let certificate = if let Some(key) = &key {
        let certificate = X509::from_pem(
            prepared
                .engine
                .client_cert_pem
                .as_ref()
                .context("Missing OpenVPN client certificate")?
                .as_bytes(),
        )
        .context("Invalid OpenVPN client certificate")?;
        ensure!(
            certificate.public_key()?.public_eq(key),
            "OpenVPN client certificate does not match its key"
        );
        Some(hex::encode(certificate.digest(MessageDigest::sha256())?))
    } else {
        None
    };
    let cancel = CancellationToken::new();
    let (question_tx, mut questions) = mpsc::channel::<Question>(1);
    let (connected_tx, mut connected_rx) = mpsc::channel::<Result<Connected, String>>(1);
    let (tx, from_tun) = mpsc::channel(QUEUE_PACKETS);
    let (to_tun, rx) = mpsc::channel(QUEUE_PACKETS);
    let finished = Arc::new(Mutex::new(None));
    let broker = Arc::new(Broker {
        password: Mutex::new(Some(Zeroizing::new(password.to_owned()))),
        key,
        certificate,
        questions: question_tx,
        cancel: cancel.clone(),
    });
    let ctx = SessionContext {
        name: profile.name.clone(),
        prompter: broker,
        cancel: cancel.clone(),
        stats: Arc::default(),
    };
    let engine_profile = prepared.engine.clone();
    let final_state = finished.clone();
    let (worker_finished, worker_done) = std::sync::mpsc::channel();
    let worker = thread::Builder::new()
        .name("sslray-openvpn".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(_) => {
                    let _ = connected_tx.blocking_send(Err("Cannot start OpenVPN runtime".into()));
                    let _ = worker_finished.send(());
                    return;
                }
            };
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.block_on(async move {
                let mut engine = OpenVpnEngine::new(engine_profile);
                let result: Result<()> = async {
                    let settings = tokio::select! {
                        _ = ctx.cancel.cancelled() => bail!("OpenVPN connection cancelled"),
                        result = tokio::time::timeout(CONNECT_TIMEOUT, engine.connect(&ctx)) => result.context("OpenVPN connection deadline exceeded")??,
                    };
                    let (peer, cipher, transport) = engine
                        .connection_metadata()
                        .context("Missing OpenVPN connected peer")?;
                    ensure!(
                        peer.is_ipv4(),
                        "SSLRay OpenVPN currently requires an IPv4 outer peer"
                    );
                    connected_tx
                        .send(Ok(Connected {
                            settings,
                            peer,
                            cipher,
                            transport,
                        }))
                        .await
                        .map_err(|_| anyhow::anyhow!("OpenVPN connection owner closed"))?;
                    tokio::select! {
                    _ = async { ctx.cancel.cancelled().await; tokio::time::sleep(Duration::from_millis(250)).await; } => Ok(()),
                        result = engine.run(&ctx, PacketIo { to_tun, from_tun }) => result,
                    }
                }
                .await;
                let _ = engine.disconnect().await;
                let public_result = result.as_ref().map(|_| ()).map_err(safe_failure);
                if let Err(message) = &public_result {
                    let _ = connected_tx.try_send(Err(message.clone()));
                }
                if let Ok(mut state) = final_state.lock() {
                    *state = Some(public_result);
                }
            })));
            // DNS uses the OS resolver. Cancellation drops every engine future and
            // secret before stopping the runtime; do not wait forever on an OS DNS call.
            runtime.shutdown_timeout(Duration::from_secs(1));
            let _ = worker_finished.send(());
        })
        .context("Cannot create OpenVPN worker")?;
    let mut channel = Channel {
        tx: Some(tx),
        rx,
        cancel,
        worker: Some(worker),
        worker_done,
        finished,
        budget_us: AtomicU64::new(50_000),
        peer: Ipv4Addr::UNSPECIFIED,
    };
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let connected = loop {
        ensure!(
            Instant::now() < deadline,
            "OpenVPN connection deadline exceeded"
        );
        match connected_rx.try_recv() {
            Ok(result) => break result.map_err(anyhow::Error::msg)?,
            Err(mpsc::error::TryRecvError::Disconnected) => {
                bail!("OpenVPN connection worker stopped")
            }
            Err(mpsc::error::TryRecvError::Empty) => {}
        }
        match questions.try_recv() {
            Ok(question) => {
                let answer = challenge("otp");
                let _ = question.reply.send(answer);
            }
            Err(mpsc::error::TryRecvError::Disconnected)
            | Err(mpsc::error::TryRecvError::Empty) => thread::sleep(Duration::from_millis(5)),
        }
    };
    let std::net::IpAddr::V4(peer) = connected.peer.ip() else {
        bail!("OpenVPN outer peer must use IPv4");
    };
    channel.peer = peer;
    let mut routes = if prepared.pull_routes {
        connected
            .settings
            .routes
            .iter()
            .filter(|r| r.prefix_len() > 0)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    routes.extend(prepared.routes.iter().cloned());
    routes.sort();
    routes.dedup();
    Ok(BackendConnection {
        vip: connected.settings.address,
        routes,
        dns: connected
            .settings
            .dns
            .servers
            .iter()
            .filter_map(|ip| {
                if let std::net::IpAddr::V4(ip) = ip {
                    Some(*ip)
                } else {
                    None
                }
            })
            .collect(),
        negotiated_mtu: Some(prepared.mtu.map_or(connected.settings.mtu, |mtu| {
            mtu.min(connected.settings.mtu)
        })),
        cipher: connected.cipher,
        transport: format!(
            "OpenVPN/{}",
            if connected.transport == Transport::Udp {
                "UDP"
            } else {
                "TCP"
            }
        ),
        channel: Box::new(channel),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tokenizer_honors_quotes_and_refuses_truncated_input() {
        assert_eq!(
            words("ca \"my keys/ca.crt\" # comment").unwrap(),
            ["ca", "my keys/ca.crt"]
        );
        assert_eq!(
            words("static-challenge 'Enter token' 0").unwrap(),
            ["static-challenge", "Enter token", "0"]
        );
        assert!(words("key 'unterminated").is_err());
    }
    #[test]
    fn packet_queue_congestion_does_not_block_shutdown() {
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(Bytes::from_static(b"first")).unwrap();
        assert!(matches!(
            tx.try_send(Bytes::from_static(b"second")),
            Err(mpsc::error::TrySendError::Full(_))
        ));
        rx.close();
        assert!(matches!(
            tx.try_send(Bytes::new()),
            Err(mpsc::error::TrySendError::Closed(_))
        ));
    }
}
