//! App-scoped privileged helper. Credentials cross only an authenticated local socket.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sslray_core::{
    config::Profile,
    platform,
    session::{self, Event},
};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{Ipv4Addr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
use std::os::unix::{
    fs::DirBuilderExt,
    io::AsRawFd,
    net::{UnixListener, UnixStream},
};

// Unix uses a 0700 directory and checks the helper's kernel-reported root identity.
// Windows binds the same-executable elevated peer to the GUI PID and a 256-bit nonce.
enum Channel {
    #[cfg(unix)]
    Unix(UnixStream),
    Tcp(TcpStream),
}
impl Channel {
    fn set_nonblocking(&self, nonblocking: bool) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.set_nonblocking(nonblocking),
            Self::Tcp(s) => s.set_nonblocking(nonblocking),
        }
    }
    fn set_read_timeout(&self, d: Option<Duration>) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.set_read_timeout(d),
            Self::Tcp(s) => s.set_read_timeout(d),
        }
    }
    fn read_timeout(&self) -> std::io::Result<Option<Duration>> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.read_timeout(),
            Self::Tcp(s) => s.read_timeout(),
        }
    }
    fn set_write_timeout(&self, d: Option<Duration>) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.set_write_timeout(d),
            Self::Tcp(s) => s.set_write_timeout(d),
        }
    }
    fn shutdown(&self) {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
            Self::Tcp(s) => {
                let _ = s.shutdown(std::net::Shutdown::Both);
            }
        }
    }
    fn try_clone(&self) -> std::io::Result<Self> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => Ok(Self::Unix(s.try_clone()?)),
            Self::Tcp(s) => Ok(Self::Tcp(s.try_clone()?)),
        }
    }
}
impl Read for Channel {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.read(b),
            Self::Tcp(s) => s.read(b),
        }
    }
}
impl Write for Channel {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.write(b),
            Self::Tcp(s) => s.write(b),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(s) => s.flush(),
            Self::Tcp(s) => s.flush(),
        }
    }
}
#[cfg(unix)]
struct SocketGuard(std::path::PathBuf);
#[cfg(unix)]
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.0.join("helper.sock"));
        let _ = std::fs::remove_dir(&self.0);
    }
}
#[cfg(unix)]
fn verify_root_peer(socket: &UnixStream) -> Result<()> {
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        let (mut uid, mut gid) = (0, 0);
        ensure!(
            unsafe { libc::getpeereid(socket.as_raw_fd(), &mut uid, &mut gid) } == 0,
            "Cannot verify helper identity"
        );
        ensure!(uid == 0, "Helper peer is not root");
    }
    #[cfg(target_os = "linux")]
    {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of_val(&cred) as libc::socklen_t;
        ensure!(
            unsafe {
                libc::getsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    &mut cred as *mut _ as *mut _,
                    &mut len,
                )
            } == 0,
            "Cannot verify helper identity"
        );
        ensure!(cred.uid == 0, "Helper peer is not root");
    }
    Ok(())
}

const MAX_MESSAGE: usize = 1024 * 1024;
#[derive(Clone, Debug, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    AwaitingOtp,
    Connected,
    Disconnecting,
    Failed,
}
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub session_generation: u64,
    pub state: ConnectionState,
    pub message: String,
    pub credentials_rejected: bool,
    pub authorization_failed: bool,
    pub challenge: Option<String>,
    pub interface: Option<String>,
    pub address: Option<String>,
    pub cipher: Option<String>,
    pub transport: Option<String>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub elapsed_secs: u64,
    pub logs: Vec<String>,
    pub advertised_routes: Vec<String>,
    pub applied_routes: Vec<String>,
}
impl Default for Snapshot {
    fn default() -> Self {
        Self {
            session_generation: 0,
            state: ConnectionState::Disconnected,
            credentials_rejected: false,
            authorization_failed: false,
            challenge: None,
            message: "Ready to connect".into(),
            interface: None,
            address: None,
            cipher: None,
            transport: None,
            tx_bytes: 0,
            rx_bytes: 0,
            elapsed_secs: 0,
            logs: vec![],
            advertised_routes: vec![],
            applied_routes: vec![],
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    profile: Profile,
    password: String,
    otp: Option<String>,
}
impl Drop for Request {
    fn drop(&mut self) {
        self.profile.openvpn_config.zeroize();
        self.password.zeroize();
        if let Some(otp) = &mut self.otp {
            otp.zeroize();
        }
    }
}

pub struct Controller {
    session_generation: u64,
    snapshot: Snapshot,
    events: Option<Receiver<Event>>,
    cancel: Arc<AtomicBool>,
    otp_sender: Option<mpsc::Sender<Zeroizing<String>>>,
    authority: Arc<Authority>,
    elevation_method: platform::ElevationMethod,
}
impl Controller {
    pub fn new() -> Self {
        Self {
            session_generation: 0,
            snapshot: Snapshot::default(),
            events: None,
            cancel: Arc::new(AtomicBool::new(false)),
            otp_sender: None,
            authority: Arc::new(Authority::default()),
            elevation_method: platform::ElevationMethod::Automatic,
        }
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn is_busy(&self) -> bool {
        self.events.is_some()
    }
    /// A user explicitly chose the system password dialog for the next attempt.
    /// This never changes the system's authentication policy or saved settings.
    #[cfg(target_os = "macos")]
    pub fn prefer_password_authorization_once(&mut self) {
        if !self.is_busy() && !self.authority.closed.load(Ordering::Relaxed) {
            self.elevation_method = platform::ElevationMethod::Password;
        }
    }
    #[cfg(target_os = "macos")]
    pub fn clear_authorization_preference(&mut self) {
        self.elevation_method = platform::ElevationMethod::Automatic;
    }
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn pending_elevation_method(&self) -> platform::ElevationMethod {
        self.elevation_method
    }
    /// End app-scoped authorization as well as the active VPN session.
    pub fn shutdown(&mut self) {
        self.disconnect();
        self.authority.shutdown();
        self.elevation_method = platform::ElevationMethod::Automatic;
    }
    /// Clear the previous profile's metrics without discarding its reusable helper.
    pub fn reset_snapshot(&mut self) -> bool {
        if self.events.is_some() {
            return false;
        }
        self.elevation_method = platform::ElevationMethod::Automatic;
        self.snapshot = Snapshot {
            session_generation: self.session_generation,
            ..Snapshot::default()
        };
        true
    }
    pub fn connect(
        &mut self,
        profile: Profile,
        password: String,
        otp: Option<String>,
    ) -> Result<()> {
        // Own and erase credentials even when user-side file preparation fails.
        let mut request = Request {
            profile,
            password,
            otp,
        };
        ensure!(
            self.events.is_none(),
            "A VPN operation is already in progress"
        );
        // Consume the choice even if this attempt fails local validation. A
        // later unrelated connection returns to automatic authentication.
        let elevation_method = std::mem::replace(
            &mut self.elevation_method,
            platform::ElevationMethod::Automatic,
        );
        // A fresh user-initiated attempt must not retain an earlier failure's
        // retry guidance if file preparation or preflight validation fails.
        self.snapshot.authorization_failed = false;
        self.snapshot.credentials_rejected = false;
        let prepared = sslray_core::openvpn::prepare(&request.profile)?;
        request.profile.zeroize();
        request.profile = prepared;
        request.profile.validate()?;
        sslray_core::crypto::connector(&request.profile)?;
        let (otp_tx, otp_rx) = mpsc::channel();
        self.otp_sender = Some(otp_tx);
        let (tx, rx) = mpsc::channel();
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        self.snapshot = Snapshot {
            session_generation: self.session_generation,
            state: ConnectionState::Connecting,
            message: "Waiting for administrator authorization".into(),
            ..Snapshot::default()
        };
        self.events = Some(rx);
        let authority = self.authority.clone();
        thread::spawn(move || {
            let result = run_client(request, cancel, otp_rx, &authority, elevation_method, |e| {
                let _ = tx.send(e);
            });
            if let Err(e) = result {
                let _ = tx.send(Event::Error {
                    message: format!("{e:#}"),
                });
            }
            let _ = tx.send(Event::Disconnected);
        });
        Ok(())
    }
    pub fn submit_otp(&mut self, otp: String) -> Result<()> {
        let otp = Zeroizing::new(otp);
        ensure!(
            self.snapshot.state == ConnectionState::AwaitingOtp,
            "No second-password challenge pending"
        );
        ensure!(
            !otp.is_empty() && otp.len() <= 31 && !otp.contains('\0'),
            "Temporary password must be 1..31 bytes"
        );
        self.otp_sender
            .as_ref()
            .context("VPN worker stopped")?
            .send(otp)
            .map_err(|_| anyhow::anyhow!("VPN worker stopped"))?;
        self.snapshot.state = ConnectionState::Connecting;
        self.snapshot.challenge = None;
        self.snapshot.message = "Submitting temporary password".into();
        Ok(())
    }
    pub fn disconnect(&mut self) {
        if self.events.is_some() {
            self.cancel.store(true, Ordering::Relaxed);
            self.snapshot.state = ConnectionState::Disconnecting;
            self.snapshot.message = "Disconnecting and removing split routes".into();
        }
    }
    pub fn poll(&mut self) {
        let mut events = vec![];
        if let Some(rx) = &self.events {
            while let Ok(event) = rx.try_recv() {
                events.push(event);
            }
        }
        for event in events {
            match event {
                Event::Status { message } => {
                    self.snapshot.message = message.clone();
                    self.snapshot.logs.push(message);
                }
                Event::Connected {
                    interface,
                    address,
                    cipher,
                    transport,
                } => {
                    self.session_generation = self.session_generation.saturating_add(1);
                    self.snapshot.session_generation = self.session_generation;
                    self.snapshot.state = ConnectionState::Connected;
                    self.snapshot.interface = Some(interface);
                    self.snapshot.address = Some(address);
                    self.snapshot.cipher = Some(cipher);
                    self.snapshot.message = format!("Connected over {transport}");
                    self.snapshot.transport = Some(transport);
                }
                Event::Routes {
                    advertised_routes,
                    applied_routes,
                } => {
                    self.snapshot.advertised_routes = advertised_routes;
                    self.snapshot.applied_routes = applied_routes;
                }
                Event::Challenge { method } => {
                    self.snapshot.state = ConnectionState::AwaitingOtp;
                    self.snapshot.challenge = Some(method);
                    self.snapshot.message = "Enter the temporary second password".into();
                }
                Event::Stats {
                    tx_bytes,
                    rx_bytes,
                    elapsed_secs,
                } => {
                    self.snapshot.tx_bytes = tx_bytes;
                    self.snapshot.rx_bytes = rx_bytes;
                    self.snapshot.elapsed_secs = elapsed_secs;
                }
                Event::Error { message } => {
                    self.snapshot.credentials_rejected = is_credentials_rejected(&message);
                    self.snapshot.authorization_failed = is_authorization_failed(&message);
                    self.snapshot.state = ConnectionState::Failed;
                    self.snapshot.message = message.clone();
                    self.snapshot.logs.push(message);
                }
                Event::Disconnected => {
                    self.events = None;
                    self.otp_sender = None;
                    self.snapshot.challenge = None;
                    // The helper acknowledges completion only after the session
                    // returned and the tunnel handle was dropped. Keep route
                    // cleanup diagnostics, but never present its old interface.
                    self.snapshot.interface = None;
                    self.snapshot.address = None;
                    if self.snapshot.state != ConnectionState::Failed {
                        self.snapshot.state = ConnectionState::Disconnected;
                        self.snapshot.message = "Disconnected; split routes removed".into();
                    }
                }
            }
            if self.snapshot.logs.len() > 200 {
                self.snapshot.logs.remove(0);
            }
        }
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        self.authority.shutdown();
    }
}

fn read_line_limited(reader: &mut impl BufRead) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());
    loop {
        let available = reader.fill_buf()?;
        ensure!(!available.is_empty(), "Helper channel closed");
        let n = available
            .iter()
            .position(|&b| b == b'\n')
            .map(|n| n + 1)
            .unwrap_or(available.len());
        ensure!(bytes.len() + n <= MAX_MESSAGE, "IPC message exceeds limit");
        bytes.extend_from_slice(&available[..n]);
        reader.consume(n);
        if bytes.last() == Some(&b'\n') {
            break;
        }
    }
    Ok(Zeroizing::new(String::from_utf8(bytes.to_vec())?))
}

fn helper_reader(socket: Channel) -> Result<BufReader<Channel>> {
    // Darwin/BSD can inherit O_NONBLOCK from the listener. Socket timeouts do
    // not clear it, so normalize every accepted stream before reading/writing.
    socket
        .set_nonblocking(false)
        .context("Configuring privileged helper channel")?;
    socket.set_read_timeout(Some(Duration::from_millis(250)))?;
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    Ok(BufReader::new(socket))
}

fn read_helper_reply(
    reader: &mut BufReader<Channel>,
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<Zeroizing<String>> {
    let deadline = Instant::now() + timeout;
    ensure!(!cancel.load(Ordering::Relaxed), "Connection cancelled");
    ensure!(!timeout.is_zero(), "Privileged helper response timed out");
    let slice = Some(timeout.min(Duration::from_millis(250)));
    // Avoid resetting the same option between chunks: on Darwin a fully
    // disconnected peer makes setsockopt fail even with unread bytes queued.
    if reader.get_ref().read_timeout()? != slice {
        reader.get_mut().set_read_timeout(slice)?;
    }
    let mut bytes = Zeroizing::new(Vec::new());
    loop {
        ensure!(!cancel.load(Ordering::Relaxed), "Connection cancelled");
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "Privileged helper response timed out");
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        ensure!(!cancel.load(Ordering::Relaxed), "Connection cancelled");
        ensure!(
            Instant::now() < deadline,
            "Privileged helper response timed out"
        );
        ensure!(!available.is_empty(), "Helper channel closed");
        let n = available
            .iter()
            .position(|&b| b == b'\n')
            .map(|n| n + 1)
            .unwrap_or(available.len());
        ensure!(bytes.len() + n <= MAX_MESSAGE, "IPC message exceeds limit");
        bytes.extend_from_slice(&available[..n]);
        reader.consume(n);
        if bytes.last() == Some(&b'\n') {
            return Ok(Zeroizing::new(String::from_utf8(bytes.to_vec())?));
        }
    }
}

fn send_json(writer: &mut impl Write, value: &impl Serialize) -> Result<()> {
    let mut line = Zeroizing::new(serde_json::to_vec(value)?);
    line.push(b'\n');
    writer.write_all(&line)?;
    writer.flush()?;
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Control {
    Probe { challenge: String },
    Connect { request: Request },
    Disconnect,
    Otp { value: String },
    Shutdown,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    ready: String,
}

const HELPER_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const HELPER_AUTH_LIFETIME: Duration = Duration::from_secs(60 * 60);

#[derive(Default)]
struct Authority {
    pool: Mutex<Option<HelperChannel>>,
    closed: AtomicBool,
}
impl Authority {
    fn shutdown(&self) {
        self.closed.store(true, Ordering::Relaxed);
        // A running worker observes closed and cancels its own session; never
        // block the GUI while routes are being removed.
        if let Ok(mut pool) = self.pool.try_lock() {
            pool.take();
        }
    }
}
struct HelperChannel {
    reader: BufReader<Channel>,
    #[cfg(unix)]
    _socket_guard: SocketGuard,
}
impl Drop for HelperChannel {
    fn drop(&mut self) {
        let _ = send_json(self.reader.get_mut(), &Control::Shutdown);
        self.reader.get_mut().shutdown();
    }
}
impl HelperChannel {
    fn probe(&mut self, cancel: &AtomicBool) -> Result<()> {
        let mut bytes = [0; 16];
        getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("Creating helper probe: {e}"))?;
        let challenge = hex::encode(bytes);
        send_json(
            self.reader.get_mut(),
            &Control::Probe {
                challenge: challenge.clone(),
            },
        )?;
        let line = read_helper_reply(&mut self.reader, Duration::from_secs(2), cancel)
            .context("Checking privileged helper readiness")?;
        let reply: Ready = serde_json::from_str(&line)?;
        ensure!(reply.ready == challenge, "Invalid helper probe response");
        Ok(())
    }
}

/// Only errors generated by our backends after an explicit authentication
/// rejection qualify. Transport, certificate, device and OTP failures do not.
fn is_credentials_rejected(message: &str) -> bool {
    message.starts_with("Native Huawei gateway rejected authentication (status ")
        || message.starts_with("Gateway rejected authentication (status ")
        || message.starts_with("Gateway rejected authentication (legacy ReloginCause ")
        || message == "OpenVPN authentication failed"
        || matches!(
            message,
            "Cisco authentication rejected (HTTP 401); no automatic retry"
                | "Cisco authentication rejected (HTTP 403); no automatic retry"
        )
}

/// Classify only errors emitted while acquiring or verifying a privileged
/// helper. Never infer authorization failure from an arbitrary "denied" text.
fn is_authorization_failed(message: &str) -> bool {
    message == "Administrator authorization failed"
        || message.starts_with("Administrator authorization failed: ")
        || message == "Administrator authorization timed out"
        || message == "Administrator authorization cancelled"
        || message == "Helper requires administrator privileges"
        || message.starts_with("Administrator authorization/helper failed (")
        || message.starts_with("Administrator biometric authorization not completed")
}

fn wait_otp(
    receiver: &Receiver<Zeroizing<String>>,
    cancel: &AtomicBool,
) -> Result<Zeroizing<String>> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        ensure!(!cancel.load(Ordering::Relaxed), "Authentication cancelled");
        ensure!(
            Instant::now() < deadline,
            "Temporary password challenge timed out"
        );
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(value) => return Ok(value),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(_) => bail!("Temporary password input channel closed"),
        }
    }
}
fn run_client(
    mut request: Request,
    cancel: Arc<AtomicBool>,
    otp_rx: Receiver<Zeroizing<String>>,
    authority: &Authority,
    elevation_method: platform::ElevationMethod,
    mut emit: impl FnMut(Event),
) -> Result<()> {
    if platform::is_admin() {
        let mut preprovided = request.otp.take().map(Zeroizing::new);
        let output = std::cell::RefCell::new(&mut emit);
        return session::run_with_challenge(
            &request.profile,
            &request.password,
            cancel.clone(),
            |e| (output.borrow_mut())(e),
            |method| {
                if let Some(otp) = preprovided.take() {
                    return Ok(otp);
                }
                (output.borrow_mut())(Event::Challenge {
                    method: method.into(),
                });
                wait_otp(&otp_rx, &cancel)
            },
        );
    }
    ensure!(
        !authority.closed.load(Ordering::Relaxed),
        "Application is closing"
    );
    let mut pool = authority
        .pool
        .lock()
        .map_err(|_| anyhow::anyhow!("Helper pool lock failed"))?;
    if pool
        .as_mut()
        .is_some_and(|helper| helper.probe(&cancel).is_err())
    {
        pool.take();
    }
    ensure!(!cancel.load(Ordering::Relaxed), "Connection cancelled");
    if pool.is_none() {
        emit(Event::Status {
            message: "Waiting for administrator authorization".into(),
        });
        // This prefix is scoped to privilege acquisition only. Gateway
        // authentication and later network/IPC failures remain distinct.
        let mut helper = launch_helper(&cancel, elevation_method)
            .context("Administrator authorization failed")?;
        helper
            .probe(&cancel)
            .context("Administrator authorization failed")?;
        *pool = Some(helper);
    } else {
        emit(Event::Status {
            message: "Reusing administrator authorization".into(),
        });
    }
    let result = run_remote_session(
        pool.as_mut()
            .context("Privileged helper unavailable after authorization")?,
        request,
        &cancel,
        &otp_rx,
        authority,
        &mut emit,
    );
    if result.is_err() || authority.closed.load(Ordering::Relaxed) {
        pool.take();
    }
    result
}

fn launch_helper(
    cancel: &AtomicBool,
    elevation_method: platform::ElevationMethod,
) -> Result<HelperChannel> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("Creating helper nonce: {e}"))?;
    let token = hex::encode(nonce);
    #[cfg(unix)]
    let socket_guard = {
        let path = std::env::temp_dir().join(format!("sslray-{}", &token[..24]));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        SocketGuard(path)
    };
    #[cfg(unix)]
    let endpoint = socket_guard.0.join("helper.sock");
    #[cfg(unix)]
    let listener = UnixListener::bind(&endpoint)?;
    #[cfg(windows)]
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    #[cfg(windows)]
    let port = listener.local_addr()?.port();
    let executable = std::env::current_exe()?.canonicalize()?;
    let expected_token = token.clone();
    let (elev_tx, elev_rx) = mpsc::channel();
    thread::spawn(move || {
        #[cfg(unix)]
        let result = platform::request_elevation_socket_with_method(
            &executable,
            &endpoint,
            &token,
            elevation_method,
        );
        #[cfg(windows)]
        let result = platform::request_elevation(&executable, port, &token);
        #[cfg(windows)]
        let _ = elevation_method;
        let _ = elev_tx.send(result);
    });
    let deadline = Instant::now() + Duration::from_secs(120);
    let channel = loop {
        if cancel.load(Ordering::Relaxed) {
            bail!("Connection cancelled");
        }
        ensure!(
            Instant::now() < deadline,
            "Administrator authorization timed out"
        );
        if let Ok(result) = elev_rx.try_recv() {
            result.context("Administrator authorization failed")?;
        }
        match listener.accept() {
            Ok((socket, _address)) => {
                #[cfg(unix)]
                {
                    if verify_root_peer(&socket).is_err() {
                        continue;
                    }
                }
                #[cfg(unix)]
                let socket = Channel::Unix(socket);
                #[cfg(windows)]
                {
                    if sslray_core::windows_peer::verify_elevated_peer(
                        &socket,
                        &std::env::current_exe()?,
                    )
                    .is_err()
                    {
                        continue;
                    }
                }
                #[cfg(windows)]
                let socket = Channel::Tcp(socket);
                let mut reader = helper_reader(socket)?;
                let line = read_helper_reply(&mut reader, Duration::from_secs(2), cancel)
                    .context("Reading privileged helper greeting")?;
                if line.trim() != expected_token {
                    continue;
                }
                break reader;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50))
            }
            Err(e) => return Err(e.into()),
        }
    };
    Ok(HelperChannel {
        reader: channel,
        #[cfg(unix)]
        _socket_guard: socket_guard,
    })
}

fn run_remote_session(
    helper: &mut HelperChannel,
    request: Request,
    cancel: &AtomicBool,
    otp_rx: &Receiver<Zeroizing<String>>,
    authority: &Authority,
    emit: &mut impl FnMut(Event),
) -> Result<()> {
    let channel = &mut helper.reader;
    channel
        .get_mut()
        .set_read_timeout(Some(Duration::from_millis(250)))?;
    ensure!(!cancel.load(Ordering::Relaxed), "Connection cancelled");
    ensure!(
        !authority.closed.load(Ordering::Relaxed),
        "Application is closing"
    );
    send_json(channel.get_mut(), &Control::Connect { request })?;
    let mut sent_cancel = false;
    let mut partial = Zeroizing::new(Vec::<u8>::new());
    loop {
        if (cancel.load(Ordering::Relaxed) || authority.closed.load(Ordering::Relaxed))
            && !sent_cancel
        {
            send_json(channel.get_mut(), &Control::Disconnect)?;
            sent_cancel = true;
        }
        if let Ok(otp) = otp_rx.try_recv() {
            let mut command = Control::Otp {
                value: otp.to_string(),
            };
            let result = send_json(channel.get_mut(), &command);
            if let Control::Otp { value } = &mut command {
                value.zeroize();
            }
            result?;
        }
        // Preserve partial JSON across timeouts.
        let remaining = MAX_MESSAGE.saturating_sub(partial.len());
        ensure!(remaining > 0, "Helper event exceeds limit");
        match Read::take(&mut *channel, remaining as u64).read_until(b'\n', &mut partial) {
            Ok(0) => bail!("Privileged helper channel closed"),
            Ok(_) => {
                ensure!(partial.len() <= MAX_MESSAGE, "Helper event exceeds limit");
                if partial.last() == Some(&b'\n') {
                    let event: Event = serde_json::from_slice(&partial)?;
                    let done = matches!(event, Event::Disconnected);
                    emit(event);
                    partial.clear();
                    if done {
                        break;
                    }
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

pub fn helper(
    port: Option<u16>,
    path: Option<&std::path::Path>,
    parent_pid: Option<u32>,
    token: &str,
) -> Result<()> {
    #[cfg(not(windows))]
    let _ = parent_pid;
    ensure!(
        platform::is_admin(),
        "Helper requires administrator privileges"
    );
    ensure!(
        token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid helper token"
    );
    let mut socket = if let Some(path) = path {
        #[cfg(unix)]
        {
            Channel::Unix(UnixStream::connect(path)?)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            bail!("Unix sockets are unavailable on this platform");
        }
    } else {
        Channel::Tcp(TcpStream::connect_timeout(
            &(Ipv4Addr::LOCALHOST, port.context("Missing helper port")?).into(),
            Duration::from_secs(5),
        )?)
    };
    #[cfg(windows)]
    {
        let Channel::Tcp(ref stream) = socket;
        sslray_core::windows_peer::verify_server_peer(
            stream,
            &std::env::current_exe()?,
            parent_pid.context("Missing original GUI process ID")?,
        )?;
    }
    socket.set_write_timeout(Some(Duration::from_secs(5)))?;
    socket.set_read_timeout(Some(Duration::from_secs(15)))?;
    socket.write_all(format!("{token}\n").as_bytes())?;
    serve_helper(
        socket,
        HELPER_IDLE_TIMEOUT,
        HELPER_AUTH_LIFETIME,
        run_privileged_session,
    )
}

#[derive(Clone)]
struct RunningSession {
    cancel: Arc<AtomicBool>,
    otp: mpsc::SyncSender<Zeroizing<String>>,
}
enum HelperInput {
    Probe(String),
    Connect(Box<Request>, Arc<AtomicBool>, Receiver<Zeroizing<String>>),
}

fn serve_helper(
    mut socket: Channel,
    idle_timeout: Duration,
    auth_lifetime: Duration,
    mut run_session: impl FnMut(
        Request,
        Arc<AtomicBool>,
        Receiver<Zeroizing<String>>,
        &mut Channel,
    ) -> Result<()>,
) -> Result<()> {
    let mut reader = BufReader::new(socket.try_clone()?);
    reader.get_mut().set_read_timeout(None)?;
    let state = Arc::new(Mutex::new(None::<RunningSession>));
    let closed = Arc::new(AtomicBool::new(false));
    // Only one pending request is allowed; even authenticated clients cannot
    // queue an unbounded number of credential-bearing messages.
    let (input_tx, input_rx) = mpsc::sync_channel(1);
    let reader_state = state.clone();
    let reader_closed = closed.clone();
    let worker = thread::spawn(move || {
        while let Ok(line) = read_line_limited(&mut reader) {
            let Ok(command) = serde_json::from_str::<Control>(&line) else {
                break;
            };
            let Ok(mut current) = reader_state.lock() else {
                break;
            };
            match command {
                Control::Probe { challenge } => {
                    if current.is_some()
                        || challenge.len() != 32
                        || !challenge.bytes().all(|b| b.is_ascii_hexdigit())
                        || input_tx.try_send(HelperInput::Probe(challenge)).is_err()
                    {
                        break;
                    }
                }
                Control::Connect { request } => {
                    if current.is_some() {
                        break;
                    }
                    let cancel = Arc::new(AtomicBool::new(false));
                    let (otp_tx, otp_rx) = mpsc::sync_channel(1);
                    *current = Some(RunningSession {
                        cancel: cancel.clone(),
                        otp: otp_tx,
                    });
                    if input_tx
                        .try_send(HelperInput::Connect(Box::new(request), cancel, otp_rx))
                        .is_err()
                    {
                        break;
                    }
                }
                Control::Disconnect => {
                    if let Some(current) = &*current {
                        current.cancel.store(true, Ordering::Relaxed);
                    }
                }
                Control::Otp { value } => {
                    let value = Zeroizing::new(value);
                    if value.is_empty() || value.len() > 31 || value.contains('\0') {
                        break;
                    }
                    if let Some(current) = &*current {
                        if current.otp.try_send(value).is_err() {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                Control::Shutdown => break,
            }
        }
        reader_closed.store(true, Ordering::Relaxed);
        if let Ok(current) = reader_state.lock()
            && let Some(current) = &*current
        {
            current.cancel.store(true, Ordering::Relaxed);
        }
    });
    let authorized_at = Instant::now();
    let mut last_session = authorized_at;
    let result = (|| -> Result<()> {
        loop {
            if closed.load(Ordering::Relaxed)
                || authorized_at.elapsed() >= auth_lifetime
                || last_session.elapsed() >= idle_timeout
            {
                return Ok(());
            }
            match input_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(HelperInput::Probe(challenge)) => {
                    send_json(&mut socket, &Ready { ready: challenge })?;
                }
                Ok(HelperInput::Connect(request, cancel, otp_rx)) => {
                    let result = run_session(*request, cancel, otp_rx, &mut socket);
                    // Clear routing/worker state before acknowledging completion.
                    // A new request is accepted only after run_session returned.
                    state
                        .lock()
                        .map_err(|_| anyhow::anyhow!("Helper state lock failed"))?
                        .take();
                    last_session = Instant::now();
                    if let Err(error) = result {
                        send_json(
                            &mut socket,
                            &Event::Error {
                                message: format!("{error:#}"),
                            },
                        )?;
                    }
                    send_json(&mut socket, &Event::Disconnected)?;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
    })();
    socket.shutdown();
    let _ = worker.join();
    result
}

fn run_privileged_session(
    mut request: Request,
    cancel: Arc<AtomicBool>,
    otp_rx: Receiver<Zeroizing<String>>,
    socket: &mut Channel,
) -> Result<()> {
    request.profile.validate()?;
    let mut preprovided = request.otp.take().map(Zeroizing::new);
    let output = std::cell::RefCell::new(socket);
    let output_cancel = cancel.clone();
    session::run_with_challenge(
        &request.profile,
        &request.password,
        cancel.clone(),
        |event| {
            // The broker acknowledges Disconnected only after the session has
            // fully returned and its route/interface destructors have run.
            if !matches!(event, Event::Disconnected)
                && send_json(&mut *output.borrow_mut(), &event).is_err()
            {
                output_cancel.store(true, Ordering::Relaxed);
            }
        },
        |method| {
            if let Some(otp) = preprovided.take() {
                return Ok(otp);
            }
            send_json(
                &mut *output.borrow_mut(),
                &Event::Challenge {
                    method: method.into(),
                },
            )?;
            wait_otp(&otp_rx, &cancel)
        },
    )
}

pub fn foreground(
    profile: Profile,
    password: Zeroizing<String>,
    otp: Option<Zeroizing<String>>,
    cancel: Arc<AtomicBool>,
) -> Result<()> {
    let profile = sslray_core::openvpn::prepare(&profile)?;
    let mut failed = None;
    let authority = Authority::default();
    let (otp_tx, otp_rx) = mpsc::channel();
    run_client(
        Request {
            profile,
            password: password.to_string(),
            otp: otp.as_ref().map(|s| s.to_string()),
        },
        cancel,
        otp_rx,
        &authority,
        platform::ElevationMethod::Automatic,
        |event| {
            if let Event::Challenge { .. } = &event {
                let sender = otp_tx.clone();
                thread::spawn(move || {
                    match rpassword::prompt_password("Temporary second password: ") {
                        Ok(value) => {
                            let _ = sender.send(Zeroizing::new(value));
                        }
                        Err(e) => eprintln!("Temporary password input failed: {e}"),
                    }
                });
            }
            if let Event::Error { message } = &event {
                failed = Some(message.clone());
            }
            println!("{}", serde_json::to_string(&event).unwrap_or_default());
        },
    )?;
    if let Some(message) = failed {
        bail!(message);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_rejection_does_not_include_transport_policy_or_otp_errors() {
        for message in [
            "Native Huawei gateway rejected authentication (status -1); no automatic retry",
            "Gateway rejected authentication (status 2)",
            "Gateway rejected authentication (legacy ReloginCause 1); no automatic retry",
            "OpenVPN authentication failed",
            "Cisco authentication rejected (HTTP 401); no automatic retry",
        ] {
            assert!(is_credentials_rejected(message), "{message}");
        }
        for message in [
            "certificate verify failed",
            "Invalid helper token",
            "Administrator authorization failed",
            "OpenVPN verification code rejected",
            "Gateway rejected temporary password",
            "Gateway rejected temporary password (status 2)",
            "Native Huawei secondary authentication failed; no automatic retry: Native Huawei gateway rejected authentication (status -1); no automatic retry",
            "Cisco verification code was rejected; no automatic retry",
            "Cisco credentials rejected or unsupported additional challenge; no automatic retry",
            "Cisco authentication rejected (HTTP 500); no automatic retry",
            "Gateway rejected data channel",
            "Native Huawei gateway requires HostID device authentication",
        ] {
            assert!(!is_credentials_rejected(message), "{message}");
        }
    }

    #[test]
    fn authorization_failures_are_distinct_from_credentials_tls_and_routes() {
        for message in [
            "Administrator authorization failed",
            "Administrator authorization failed: Administrator authorization timed out",
            "Administrator authorization failed: Connection cancelled",
            "Administrator authorization failed: Install polkit/pkexec to request administrator privileges",
            "Administrator authorization failed: Administrator authorization/helper failed (exit status: 1): user cancelled",
            "Administrator authorization failed: Reading privileged helper greeting: Privileged helper response timed out",
            "Administrator authorization failed: Administrator biometric authorization not completed (exit status: 1)",
            "Administrator biometric authorization not completed: authentication unavailable",
            "Administrator authorization timed out",
            "Helper requires administrator privileges",
        ] {
            assert!(is_authorization_failed(message), "{message}");
            assert!(!is_credentials_rejected(message), "{message}");
        }
        for message in [
            "OpenVPN authentication failed",
            "Native Huawei gateway rejected authentication (status -1); no automatic retry",
            "certificate verify failed",
            "Gateway rejected temporary password",
            "Permission denied while adding route",
            "TLS handshake timed out",
            "Privileged helper channel closed",
            "Administrator authorization failed for gateway account",
        ] {
            assert!(!is_authorization_failed(message), "{message}");
        }
    }

    #[test]
    fn authorization_retry_flag_clears_on_new_attempt_even_if_preflight_fails() {
        let mut controller = Controller::new();
        let (tx, rx) = mpsc::channel();
        controller.events = Some(rx);
        tx.send(Event::Error {
            message: "Administrator authorization failed: user cancelled".into(),
        })
        .unwrap();
        tx.send(Event::Disconnected).unwrap();
        controller.poll();
        assert!(controller.snapshot.authorization_failed);
        assert!(!controller.snapshot.credentials_rejected);
        assert!(!controller.is_busy());
        let profile = Profile {
            host: String::new(),
            ..Profile::default()
        };
        assert!(controller.connect(profile, String::new(), None).is_err());
        assert!(!controller.snapshot.authorization_failed);
        assert!(!controller.is_busy());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn password_authorization_choice_is_single_attempt_and_cannot_override_active_work() {
        let mut controller = Controller::new();
        controller.prefer_password_authorization_once();
        assert_eq!(
            controller.elevation_method,
            platform::ElevationMethod::Password
        );
        let invalid = Profile {
            host: String::new(),
            ..Profile::default()
        };
        assert!(controller.connect(invalid, String::new(), None).is_err());
        assert_eq!(
            controller.elevation_method,
            platform::ElevationMethod::Automatic
        );
        let (_tx, rx) = mpsc::channel();
        controller.events = Some(rx);
        controller.prefer_password_authorization_once();
        assert_eq!(
            controller.elevation_method,
            platform::ElevationMethod::Automatic
        );
        controller.events = None;
        controller.shutdown();
        controller.prefer_password_authorization_once();
        assert_eq!(
            controller.elevation_method,
            platform::ElevationMethod::Automatic
        );
    }

    #[test]
    fn only_finished_controller_can_reset_profile_metrics() {
        let mut controller = Controller::new();
        controller.snapshot.tx_bytes = 123;
        let (_tx, rx) = mpsc::channel();
        controller.events = Some(rx);
        assert!(!controller.reset_snapshot());
        assert_eq!(controller.snapshot.tx_bytes, 123);
        controller.events = None;
        assert!(controller.reset_snapshot());
        assert_eq!(controller.snapshot.tx_bytes, 0);
        assert!(!controller.authority.closed.load(Ordering::Relaxed));
    }

    #[test]
    fn completed_sessions_clear_adapter_identity_without_losing_cleanup_errors() {
        let mut controller = Controller::new();
        for cleanup_failed in [false, true] {
            let (tx, rx) = mpsc::channel();
            controller.events = Some(rx);
            tx.send(Event::Connected {
                interface: "utun40".into(),
                address: "192.0.2.2".into(),
                cipher: "test".into(),
                transport: "TLS".into(),
            })
            .unwrap();
            tx.send(Event::Routes {
                advertised_routes: vec![],
                applied_routes: vec!["192.0.2.0/24".into()],
            })
            .unwrap();
            controller.poll();
            let generation = controller.snapshot.session_generation;
            assert!(generation > 0);
            assert_eq!(controller.snapshot.interface.as_deref(), Some("utun40"));
            if cleanup_failed {
                tx.send(Event::Error {
                    message: "Route cleanup failed".into(),
                })
                .unwrap();
            } else {
                tx.send(Event::Routes {
                    advertised_routes: vec![],
                    applied_routes: vec![],
                })
                .unwrap();
            }
            controller.poll();
            assert!(controller.is_busy());
            assert!(controller.snapshot.interface.is_some());
            tx.send(Event::Disconnected).unwrap();
            controller.poll();
            assert!(!controller.is_busy());
            assert!(
                controller.snapshot.interface.is_none() && controller.snapshot.address.is_none()
            );
            assert_eq!(
                !controller.snapshot.applied_routes.is_empty(),
                cleanup_failed
            );
            assert!(controller.reset_snapshot());
            assert_eq!(controller.snapshot.session_generation, generation);
            let invalid = Profile {
                host: String::new(),
                ..Profile::default()
            };
            assert!(controller.connect(invalid, String::new(), None).is_err());
            assert_eq!(controller.snapshot.session_generation, generation);
        }
        assert_eq!(controller.snapshot.session_generation, 2);
    }

    #[test]
    fn authentication_rejection_survives_disconnect_until_next_attempt() {
        let mut controller = Controller::new();
        let (tx, rx) = mpsc::channel();
        controller.events = Some(rx);
        tx.send(Event::Error {
            message: "OpenVPN authentication failed".into(),
        })
        .unwrap();
        tx.send(Event::Disconnected).unwrap();
        controller.poll();
        assert_eq!(controller.snapshot.state, ConnectionState::Failed);
        assert!(controller.snapshot.credentials_rejected);
        assert!(controller.reset_snapshot());
        assert!(!controller.snapshot.credentials_rejected);
    }

    #[test]
    fn ipc_input_rejects_truncated_and_oversized_messages() {
        assert!(read_line_limited(&mut &b"{}"[..]).is_err());
        let data = vec![b'x'; MAX_MESSAGE + 1];
        assert!(read_line_limited(&mut &data[..]).is_err());
        assert!(serde_json::from_str::<Control>(r#"{"command":"unexpected"}"#).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn accepted_nonblocking_helper_stream_reads_delayed_fragmented_nonce() {
        let path =
            std::env::temp_dir().join(format!("sslray-accept-{:016x}", getrandom::u64().unwrap()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        let guard = SocketGuard(path);
        let endpoint = guard.0.join("helper.sock");
        let listener = UnixListener::bind(&endpoint).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (connected_tx, connected_rx) = mpsc::channel();
        let (start_tx, start_rx) = mpsc::channel();
        let writer = thread::spawn(move || {
            let mut peer = UnixStream::connect(endpoint).unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            connected_tx.send(()).unwrap();
            start_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            thread::sleep(Duration::from_millis(25));
            peer.write_all(b"synthetic-").unwrap();
            thread::sleep(Duration::from_millis(350));
            peer.write_all(b"nonce\n").unwrap();
        });
        connected_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        // Darwin inherits this flag; explicitly set it so Linux also exercises
        // the production normalization instead of hiding the regression.
        stream.set_nonblocking(true).unwrap();
        assert_eq!(
            stream.read(&mut [0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let mut reader = helper_reader(Channel::Unix(stream)).unwrap();
        let Channel::Unix(stream) = reader.get_ref() else {
            unreachable!()
        };
        let stream_flags = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) };
        assert!(stream_flags >= 0);
        assert_eq!(stream_flags & libc::O_NONBLOCK, 0);
        let listener_flags = unsafe { libc::fcntl(listener.as_raw_fd(), libc::F_GETFL) };
        assert!(listener_flags >= 0);
        assert_ne!(listener_flags & libc::O_NONBLOCK, 0);
        start_tx.send(()).unwrap();
        let reply = read_helper_reply(&mut reader, Duration::from_secs(3), &AtomicBool::new(false))
            .unwrap();
        assert_eq!(reply.as_str(), "synthetic-nonce\n");
        writer.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fragmented_probe_ready_survives_read_slice_timeout_and_is_reusable() {
        let (mut client, server) = pair();
        let worker = thread::spawn(move || {
            server
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = BufReader::new(server);
            for attempt in 0..2 {
                let line = read_line_limited(&mut reader).unwrap();
                let Control::Probe { challenge } = serde_json::from_str(&line).unwrap() else {
                    panic!("expected a readiness probe");
                };
                let mut response = serde_json::to_vec(&Ready { ready: challenge }).unwrap();
                response.push(b'\n');
                let split = response.len() / 2;
                reader.get_mut().write_all(&response[..split]).unwrap();
                if attempt == 0 {
                    thread::sleep(Duration::from_millis(350));
                }
                reader.get_mut().write_all(&response[split..]).unwrap();
            }
        });
        let cancel = AtomicBool::new(false);
        client.probe(&cancel).unwrap();
        client.probe(&cancel).unwrap();
        worker.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn helper_reply_uses_total_deadline_instead_of_returning_raw_would_block() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let mut reader = helper_reader(Channel::Unix(stream)).unwrap();
        let started = Instant::now();
        let error = read_helper_reply(
            &mut reader,
            Duration::from_millis(40),
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "Privileged helper response timed out");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[cfg(unix)]
    #[test]
    fn helper_reply_cancellation_handles_initial_and_pending_reads_without_echo() {
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let mut reader = helper_reader(Channel::Unix(stream)).unwrap();
        let cancel = Arc::new(AtomicBool::new(true));
        let error = read_helper_reply(&mut reader, Duration::from_secs(3), &cancel).unwrap_err();
        assert_eq!(error.to_string(), "Connection cancelled");
        cancel.store(false, Ordering::Relaxed);
        let fragment = "synthetic-sensitive-fragment";
        peer.write_all(fragment.as_bytes()).unwrap();
        let worker_cancel = cancel.clone();
        let worker = thread::spawn(move || {
            thread::sleep(Duration::from_millis(40));
            worker_cancel.store(true, Ordering::Relaxed);
        });
        let started = Instant::now();
        let error = read_helper_reply(&mut reader, Duration::from_secs(3), &cancel).unwrap_err();
        assert_eq!(error.to_string(), "Connection cancelled");
        assert!(!format!("{error:#}").contains(fragment));
        assert!(started.elapsed() < Duration::from_secs(2));
        worker.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn helper_reply_eof_and_size_limit_do_not_echo_partial_contents() {
        let fragment = "synthetic-sensitive-fragment";
        let (stream, mut peer) = UnixStream::pair().unwrap();
        let mut reader = helper_reader(Channel::Unix(stream)).unwrap();
        peer.write_all(fragment.as_bytes()).unwrap();
        peer.shutdown(std::net::Shutdown::Write).unwrap();
        let cancel = AtomicBool::new(false);
        let error = read_helper_reply(&mut reader, Duration::from_secs(3), &cancel).unwrap_err();
        assert_eq!(error.to_string(), "Helper channel closed");
        assert!(!format!("{error:#}").contains(fragment));

        let (stream, mut peer) = UnixStream::pair().unwrap();
        let mut reader = helper_reader(Channel::Unix(stream)).unwrap();
        let writer = thread::spawn(move || {
            peer.set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut bytes = vec![b'x'; MAX_MESSAGE + 1];
            bytes[..fragment.len()].copy_from_slice(fragment.as_bytes());
            bytes[MAX_MESSAGE] = b'\n';
            peer.write_all(&bytes).unwrap();
        });
        let error = read_helper_reply(&mut reader, Duration::from_secs(3), &cancel).unwrap_err();
        assert_eq!(error.to_string(), "IPC message exceeds limit");
        assert!(!format!("{error:#}").contains(fragment));
        writer.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn cancelled_or_closed_session_does_not_send_connect_or_credentials() {
        for (cancelled, closed, expected) in [
            (true, false, "Connection cancelled"),
            (false, true, "Application is closing"),
        ] {
            let (mut helper, mut peer) = pair();
            peer.set_read_timeout(Some(Duration::from_millis(40)))
                .unwrap();
            let authority = Authority::default();
            authority.closed.store(closed, Ordering::Relaxed);
            let cancel = AtomicBool::new(cancelled);
            let (_otp_tx, otp_rx) = mpsc::channel();
            let mut events = Vec::new();
            let error = run_remote_session(
                &mut helper,
                Request {
                    profile: Profile::default(),
                    password: "synthetic-never-sent-password".into(),
                    otp: Some("123456".into()),
                },
                &cancel,
                &otp_rx,
                &authority,
                &mut |event| events.push(event),
            )
            .unwrap_err();
            assert_eq!(error.to_string(), expected);
            assert!(events.is_empty());
            // Keep both endpoints alive: EOF would not prove that Connect
            // (including the credentials) had never been transmitted.
            let error = peer.read(&mut [0]).unwrap_err();
            assert!(matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ));
        }
    }

    #[cfg(unix)]
    fn pair() -> (HelperChannel, Channel) {
        let (client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        server
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut random = [0; 16];
        getrandom::fill(&mut random).unwrap();
        let path =
            std::env::temp_dir().join(format!("sslray-runtime-test-{}", hex::encode(random)));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        (
            HelperChannel {
                reader: BufReader::new(Channel::Unix(client)),
                _socket_guard: SocketGuard(path),
            },
            Channel::Unix(server),
        )
    }

    #[cfg(unix)]
    fn receive_session(helper: &mut HelperChannel) -> Vec<Event> {
        helper
            .reader
            .get_mut()
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut events = Vec::new();
        loop {
            let line = read_line_limited(&mut helper.reader).unwrap();
            let event: Event = serde_json::from_str(&line).unwrap();
            let done = matches!(event, Event::Disconnected);
            events.push(event);
            if done {
                return events;
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn helper_reuses_one_channel_after_failed_and_successful_sessions() {
        let (mut client, server) = pair();
        let worker = thread::spawn(move || {
            let mut count = 0;
            serve_helper(
                server,
                Duration::from_secs(5),
                Duration::from_secs(5),
                |request, _, _, socket| {
                    count += 1;
                    assert_eq!(request.password, "test-session-password");
                    if count == 1 {
                        bail!("OpenVPN authentication failed");
                    }
                    send_json(
                        socket,
                        &Event::Status {
                            message: request.profile.name.clone(),
                        },
                    )
                },
            )
            .unwrap();
            count
        });
        for index in 0..2 {
            client.probe(&AtomicBool::new(false)).unwrap();
            let profile = Profile {
                name: format!("Profile {index}"),
                ..Profile::default()
            };
            send_json(
                client.reader.get_mut(),
                &Control::Connect {
                    request: Request {
                        profile,
                        password: "test-session-password".into(),
                        otp: None,
                    },
                },
            )
            .unwrap();
            let events = receive_session(&mut client);
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, Event::Error { .. }))
                    .count(),
                usize::from(index == 0)
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, Event::Disconnected))
                    .count(),
                1
            );
        }
        drop(client);
        assert_eq!(worker.join().unwrap(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn overlapping_connect_is_refused_and_cancels_the_existing_session() {
        let (mut client, server) = pair();
        let (started_tx, started_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut count = 0;
            let result = serve_helper(
                server,
                Duration::from_secs(5),
                Duration::from_secs(5),
                |_, cancel, _, _| {
                    count += 1;
                    started_tx.send(()).unwrap();
                    let until = Instant::now() + Duration::from_secs(2);
                    while !cancel.load(Ordering::Relaxed) {
                        assert!(
                            Instant::now() < until,
                            "overlapping request did not cancel session"
                        );
                        thread::sleep(Duration::from_millis(5));
                    }
                    Ok(())
                },
            );
            // The root side can finish with a closed-channel write.
            let _ = result;
            count
        });
        client.probe(&AtomicBool::new(false)).unwrap();
        let connect = || Control::Connect {
            request: Request {
                profile: Profile::default(),
                password: String::new(),
                otp: None,
            },
        };
        send_json(client.reader.get_mut(), &connect()).unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        send_json(client.reader.get_mut(), &connect()).unwrap();
        assert_eq!(worker.join().unwrap(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn helper_idle_and_auth_leases_expire_without_new_credentials() {
        for (idle, total) in [
            (Duration::from_millis(40), Duration::from_secs(5)),
            (Duration::from_secs(5), Duration::from_millis(40)),
        ] {
            let (mut client, server) = pair();
            let worker = thread::spawn(move || {
                serve_helper(server, idle, total, |_, _, _, _| {
                    panic!("expired helper received credentials")
                })
            });
            // Join means the helper itself expired and closed its reader.
            worker.join().unwrap().unwrap();
            assert!(client.probe(&AtomicBool::new(false)).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn parent_channel_loss_cancels_running_session_before_helper_exits() {
        let (mut client, server) = pair();
        let (started_tx, started_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            serve_helper(
                server,
                Duration::from_secs(5),
                Duration::from_secs(5),
                |_, cancel, _, _| {
                    started_tx.send(()).unwrap();
                    let until = Instant::now() + Duration::from_secs(2);
                    while !cancel.load(Ordering::Relaxed) {
                        assert!(Instant::now() < until, "lost parent did not cancel session");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Ok(())
                },
            )
        });
        client.probe(&AtomicBool::new(false)).unwrap();
        send_json(
            client.reader.get_mut(),
            &Control::Connect {
                request: Request {
                    profile: Profile::default(),
                    password: String::new(),
                    otp: None,
                },
            },
        )
        .unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        client.reader.get_mut().shutdown();
        // Completion can report a closed-channel write after cancellation.
        let _ = worker.join().unwrap();
    }
}
