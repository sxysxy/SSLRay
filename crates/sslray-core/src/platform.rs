//! Native packet interfaces, transactional split routes and OS elevation.
use anyhow::{Context, Result, bail, ensure};
#[cfg(unix)]
use std::io::{Read, Write};
use std::{
    collections::HashSet,
    fmt, io,
    net::Ipv4Addr,
    path::Path,
    process::{Command, Stdio},
    str::FromStr,
};
#[cfg(unix)]
use tun::AbstractDevice;

#[cfg(target_os = "macos")]
#[path = "macos_authorization.rs"]
mod macos_authorization;

/// A normalized IPv4 split route. The default route is deliberately excluded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv4Route {
    network: Ipv4Addr,
    prefix: u8,
}
impl Ipv4Route {
    pub fn network(self) -> Ipv4Addr {
        self.network
    }
    pub fn prefix(self) -> u8 {
        self.prefix
    }
    pub fn contains(self, address: Ipv4Addr) -> bool {
        (u32::from(address) & self.mask()) == u32::from(self.network)
    }
    fn mask(self) -> u32 {
        u32::MAX << (32 - self.prefix)
    }
}
impl fmt::Display for Ipv4Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}
impl FromStr for Ipv4Route {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        let (address, prefix) = value
            .split_once('/')
            .context("Route must be IPv4 CIDR (e.g. 10.0.0.0/8)")?;
        let address: Ipv4Addr = address.parse().context("Invalid IPv4 route address")?;
        let prefix: u8 = prefix.parse().context("Invalid IPv4 route prefix")?;
        ensure!(
            (1..=32).contains(&prefix),
            "Only split routes with prefixes 1..32 are supported"
        );
        let mask = u32::MAX << (32 - prefix);
        Ok(Self {
            network: Ipv4Addr::from(u32::from(address) & mask),
            prefix,
        })
    }
}

/// An L3 interface. Reads return WouldBlock when its packet queue is empty.
/// macOS utun's four-byte address-family prefix is handled by `tun`, never NEM.
pub struct Tunnel {
    name: String,
    #[cfg(unix)]
    device: tun::Device,
    #[cfg(target_os = "windows")]
    session: std::sync::Arc<wintun_bindings::Session>,
}
impl Tunnel {
    pub fn create(address: Ipv4Addr, mtu: u16) -> Result<Self> {
        ensure!(
            is_admin(),
            "Administrator privileges are required to configure the VPN interface"
        );
        ensure!(
            !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast(),
            "Invalid VPN address"
        );
        ensure!((576..=1500).contains(&mtu), "MTU must be 576..1500");
        #[cfg(unix)]
        {
            let mut config = tun::Configuration::default();
            config
                .address(address)
                .netmask(Ipv4Addr::BROADCAST)
                .mtu(mtu)
                .up();
            #[cfg(target_os = "macos")]
            {
                config.destination(address);
                config.platform_config(|p| {
                    p.enable_routing(false).packet_information(true);
                });
            }
            #[cfg(target_os = "linux")]
            config.platform_config(|p| {
                p.ensure_root_privileges(true);
            });
            let device = tun::create(&config).context("Creating native VPN interface")?;
            let name = device.tun_name().context("Reading VPN interface name")?;
            device
                .set_nonblock()
                .context("Setting nonblocking interface I/O")?;
            Ok(Self { name, device })
        }
        #[cfg(target_os = "windows")]
        {
            // Authenticate and lock official bytes before any DLL code executes.
            // The binding's load_from_path verifies only after an initial load.
            let wintun = crate::windows_wintun::load()
                .context("Loading Wintun from the application directory")?;
            // A new adapter per helper process avoids taking ownership of an existing VPN.
            let name = format!("SSLRay-{}", std::process::id());
            let adapter = wintun_bindings::Adapter::create(&wintun, &name, "SSLRay", None)
                .context("Creating Wintun adapter")?;
            // Use an absolute system binary instead of the binding's convenience
            // address setter, which searches PATH for netsh in a privileged process.
            let configure = CommandSpec::new(
                windows_system_binary("netsh.exe"),
                [
                    "interface".into(),
                    "ipv4".into(),
                    "set".into(),
                    "address".into(),
                    format!("name={name}"),
                    "source=static".into(),
                    format!("address={address}"),
                    "mask=255.255.255.255".into(),
                    "gateway=none".into(),
                    "store=active".into(),
                ],
            );
            let started = std::time::Instant::now();
            loop {
                match run_command(&configure) {
                    Ok(()) => break,
                    Err(_) if started.elapsed() < std::time::Duration::from_secs(5) => {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(error) => return Err(error.context("Configuring Wintun IPv4 address")),
                }
            }
            adapter
                .set_mtu(usize::from(mtu))
                .context("Configuring Wintun MTU")?;
            let session = adapter
                .start_session(4 * 1024 * 1024)
                .context("Starting Wintun session")?;
            Ok(Self { name, session })
        }
        #[cfg(not(any(unix, target_os = "windows")))]
        bail!("This operating system has no supported VPN interface backend")
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn read_packet(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            self.device.read(buffer)
        }
        #[cfg(target_os = "windows")]
        {
            self.session.try_recv(buffer)
        }
        #[cfg(not(any(unix, target_os = "windows")))]
        {
            let _ = buffer;
            Err(io::ErrorKind::Unsupported.into())
        }
    }
    pub fn write_packet(&mut self, packet: &[u8]) -> io::Result<usize> {
        #[cfg(unix)]
        {
            self.device.write(packet)
        }
        #[cfg(target_os = "windows")]
        {
            self.session.send(packet)
        }
        #[cfg(not(any(unix, target_os = "windows")))]
        {
            let _ = packet;
            Err(io::ErrorKind::Unsupported.into())
        }
    }
}
#[cfg(target_os = "windows")]
impl Drop for Tunnel {
    fn drop(&mut self) {
        let _ = self.session.shutdown();
    }
}

pub fn is_admin() -> bool {
    #[cfg(unix)]
    // SAFETY: geteuid has no preconditions and does not mutate process state.
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(target_os = "windows")]
    {
        #[link(name = "shell32")]
        unsafe extern "system" {
            fn IsUserAnAdmin() -> i32;
        }
        // SAFETY: the Windows API takes no arguments.
        unsafe { IsUserAnAdmin() != 0 }
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CommandSpec {
    program: String,
    args: Vec<String>,
}
impl CommandSpec {
    fn new(program: impl Into<String>, args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }
}
#[derive(Clone)]
struct RouteCommands {
    add: CommandSpec,
    delete: CommandSpec,
}

fn validate_interface(interface: &str) -> Result<()> {
    ensure!(
        interface
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
            && interface.len() <= 64
            && interface
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
        "Invalid VPN interface name"
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn route_commands(interface: &str, route: Ipv4Route) -> RouteCommands {
    // A Darwin network /32 and HOST route use different lookup semantics.
    // Adding a network /32 can succeed while an existing (including cloned)
    // HOST route still wins. Use the host key so a conflicting host add fails;
    // do not replace or delete the route owned by another interface.
    let (kind, destination) = if route.prefix() == 32 {
        ("-host", route.network().to_string())
    } else {
        ("-net", route.to_string())
    };
    let args = |action| {
        vec![
            "-n".into(),
            action,
            kind.into(),
            destination.clone(),
            "-interface".into(),
            interface.into(),
        ]
    };
    RouteCommands {
        add: CommandSpec::new("/sbin/route", args("add".into())),
        delete: CommandSpec::new("/sbin/route", args("delete".into())),
    }
}
#[cfg(target_os = "linux")]
fn route_commands(interface: &str, route: Ipv4Route) -> RouteCommands {
    let args = |action| {
        vec![
            "-4".into(),
            "route".into(),
            action,
            route.to_string(),
            "dev".into(),
            interface.into(),
            "proto".into(),
            "186".into(),
        ]
    };
    // iproute2 ships in /usr/sbin on common distributions; resolve only fixed system directories.
    let ip = ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .unwrap_or("/usr/sbin/ip");
    RouteCommands {
        add: CommandSpec::new(ip, args("add".into())),
        delete: CommandSpec::new(ip, args("del".into())),
    }
}
#[cfg(target_os = "windows")]
fn route_commands(interface: &str, route: Ipv4Route) -> RouteCommands {
    let args = |action| {
        vec![
            "interface".into(),
            "ipv4".into(),
            action,
            "route".into(),
            format!("prefix={route}"),
            format!("interface={interface}"),
            "nexthop=0.0.0.0".into(),
            "store=active".into(),
        ]
    };
    RouteCommands {
        add: CommandSpec::new(windows_system_binary("netsh.exe"), args("add".into())),
        delete: CommandSpec::new(windows_system_binary("netsh.exe"), args("delete".into())),
    }
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn route_commands(_: &str, _: Ipv4Route) -> RouteCommands {
    unreachable!("Unsupported platform rejected by RouteGuard::install")
}
/// A native selected route, read before adding any full-tunnel overlay.
#[derive(Clone, Debug)]
struct PeerRoute {
    peer: Ipv4Addr,
    // Command interface: native name on Unix, numeric interface index on Windows.
    interface: String,
    adapter_name: String,
    gateway: Option<Ipv4Addr>,
    existing_host: bool,
}

fn full_route_plan(interface: &str, snapshots: &[PeerRoute]) -> Result<Vec<RouteCommands>> {
    validate_interface(interface)?;
    ensure!(
        !snapshots.is_empty(),
        "Full tunnel requires outer route snapshots"
    );
    let mut plans = Vec::new();
    let mut seen = HashSet::new();
    for path in snapshots {
        validate_interface(&path.interface)?;
        ensure!(
            !path.adapter_name.eq_ignore_ascii_case(interface),
            "Outer peer {} already routes through this VPN interface",
            path.peer
        );
        ensure!(
            !path.peer.is_unspecified()
                && !path.peer.is_broadcast()
                && !path.peer.is_multicast()
                && !path.peer.is_loopback(),
            "Invalid outer peer snapshot"
        );
        if let Some(gateway) = path.gateway {
            ensure!(
                !gateway.is_unspecified() && !gateway.is_multicast() && !gateway.is_broadcast(),
                "Invalid original outer gateway"
            );
        }
        if seen.insert(path.peer) && !path.existing_host {
            plans.push(peer_pin_commands(path));
        }
    }
    // Pins are installed first. Rollback removes /1 overlays before the pins.
    plans.push(route_commands(interface, "0.0.0.0/1".parse()?));
    plans.push(route_commands(interface, "128.0.0.0/1".parse()?));
    Ok(plans)
}

fn read_command(spec: &CommandSpec) -> Result<String> {
    let output = background_command(&spec.program)
        .args(&spec.args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("Reading original route with {}", spec.program))?;
    ensure!(
        output.status.success(),
        "Could not snapshot original outer route: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    ensure!(
        output.stdout.len() <= 65536,
        "Native route response exceeds limit"
    );
    String::from_utf8(output.stdout).context("Native route response is not UTF-8")
}

#[cfg(target_os = "macos")]
fn snapshot_peer(peer: Ipv4Addr) -> Result<PeerRoute> {
    let text = read_command(&CommandSpec::new(
        "/sbin/route",
        ["-n".into(), "get".into(), peer.to_string()],
    ))?;
    parse_mac_route(peer, &text)
}
#[cfg(any(target_os = "macos", test))]
fn parse_mac_route(peer: Ipv4Addr, text: &str) -> Result<PeerRoute> {
    let value = |key: &str| {
        text.lines()
            .filter_map(|line| line.trim().split_once(':'))
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value.trim())
    };
    let interface = value("interface")
        .context("Original route has no interface")?
        .to_owned();
    validate_interface(&interface)?;
    let flags = value("flags").context("Original route has no flags")?;
    let has_flag = |flag: &str| {
        flags
            .trim_matches(['<', '>'])
            .split(',')
            .any(|item| item == flag)
    };
    ensure!(
        !has_flag("REJECT") && !has_flag("BLACKHOLE"),
        "Original outer route is not usable"
    );
    let host = has_flag("HOST") && value("destination") == Some(peer.to_string().as_str());
    // Darwin usually reports an interface-scoped WASCLONED host entry for an
    // active outer socket. It can coexist with a new unscoped static /32 pin.
    // Never reuse a scoped cache entry as our global bypass, and never delete it.
    let existing_host = host && !has_flag("IFSCOPE") && !has_flag("WASCLONED");
    ensure!(
        !(host && !has_flag("IFSCOPE") && has_flag("WASCLONED")),
        "An unscoped cloned outer host route cannot be safely pinned"
    );
    let gateway = match value("gateway") {
        None => None,
        Some(value) if value.starts_with("link#") || value.contains(':') => None,
        Some(value) => Some(
            value
                .parse::<Ipv4Addr>()
                .context("Original route gateway is not IPv4")?,
        ),
    };
    Ok(PeerRoute {
        peer,
        adapter_name: interface.clone(),
        interface,
        gateway,
        existing_host,
    })
}
#[cfg(target_os = "macos")]
fn peer_pin_commands(path: &PeerRoute) -> RouteCommands {
    let args = |action: &str| {
        let mut args = vec![
            "-n".into(),
            action.into(),
            "-host".into(),
            path.peer.to_string(),
        ];
        if let Some(gateway) = path.gateway {
            args.extend([gateway.to_string(), "-ifp".into(), path.interface.clone()]);
        } else {
            args.extend(["-interface".into(), path.interface.clone()]);
        }
        args
    };
    RouteCommands {
        add: CommandSpec::new("/sbin/route", args("add")),
        delete: CommandSpec::new("/sbin/route", args("delete")),
    }
}

#[cfg(target_os = "linux")]
fn ip_binary() -> &'static str {
    ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .unwrap_or("/usr/sbin/ip")
}
#[cfg(target_os = "linux")]
fn snapshot_peer(peer: Ipv4Addr) -> Result<PeerRoute> {
    // fibmatch returns the selected FIB prefix rather than the resolved /32 dst.
    let text = read_command(&CommandSpec::new(
        ip_binary(),
        [
            "-j".into(),
            "-4".into(),
            "route".into(),
            "get".into(),
            "fibmatch".into(),
            peer.to_string(),
        ],
    ))?;
    parse_linux_route(peer, &text)
}
#[cfg(any(target_os = "linux", test))]
fn parse_linux_route(peer: Ipv4Addr, text: &str) -> Result<PeerRoute> {
    let rows: Vec<serde_json::Value> = serde_json::from_str(text)?;
    ensure!(rows.len() == 1, "Native route lookup is ambiguous");
    let row = &rows[0];
    ensure!(
        row.get("type")
            .and_then(|v| v.as_str())
            .is_none_or(|s| s == "unicast"),
        "Original outer route is not unicast"
    );
    ensure!(
        row.get("table")
            .is_none_or(|table| table.as_u64() == Some(254) || table.as_str() == Some("main")),
        "Full tunnel with a non-main policy routing table is not supported"
    );
    let interface = row
        .get("dev")
        .and_then(|v| v.as_str())
        .context("Original route has no device")?
        .to_owned();
    validate_interface(&interface)?;
    let gateway = row
        .get("gateway")
        .and_then(|v| v.as_str())
        .map(str::parse::<Ipv4Addr>)
        .transpose()?;
    let prefix = row
        .get("dst")
        .and_then(|v| v.as_str())
        .context("Original route has no prefix")?;
    let existing_host = prefix == peer.to_string() || prefix == format!("{peer}/32");
    Ok(PeerRoute {
        peer,
        adapter_name: interface.clone(),
        interface,
        gateway,
        existing_host,
    })
}
#[cfg(target_os = "linux")]
fn peer_pin_commands(path: &PeerRoute) -> RouteCommands {
    let args = |action: &str| {
        let mut args = vec![
            "-4".into(),
            "route".into(),
            action.into(),
            format!("{}/32", path.peer),
        ];
        if let Some(gateway) = path.gateway {
            args.extend(["via".into(), gateway.to_string()]);
        }
        args.extend([
            "dev".into(),
            path.interface.clone(),
            "proto".into(),
            "186".into(),
        ]);
        args
    };
    RouteCommands {
        add: CommandSpec::new(ip_binary(), args("add")),
        delete: CommandSpec::new(ip_binary(), args("del")),
    }
}

#[cfg(target_os = "windows")]
fn snapshot_peer(peer: Ipv4Addr) -> Result<PeerRoute> {
    // Find-NetRoute returns address and route objects; retain only its one route.
    // `peer` is a typed IPv4Addr; no untrusted string is interpolated into script.
    let script = format!(
        "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $r=@(Find-NetRoute -RemoteIPAddress '{peer}' | Where-Object {{ $_.PSObject.Properties.Name -contains 'DestinationPrefix' }}); if($r.Count -ne 1){{throw 'Ambiguous original route'}}; $r[0] | Select-Object InterfaceIndex,InterfaceAlias,DestinationPrefix,NextHop | ConvertTo-Json -Compress"
    );
    let text = read_command(&CommandSpec::new(
        windows_system_binary("WindowsPowerShell/v1.0/powershell.exe"),
        ["-NoProfile", "-NonInteractive", "-Command", &script],
    ))?;
    parse_windows_route(peer, &text)
}
#[cfg(any(target_os = "windows", test))]
fn parse_windows_route(peer: Ipv4Addr, text: &str) -> Result<PeerRoute> {
    let row: serde_json::Value = serde_json::from_str(text.trim_start_matches('\u{feff}'))?;
    let index = row
        .get("InterfaceIndex")
        .and_then(|v| v.as_u64())
        .context("Original route has no interface index")?;
    ensure!(
        index > 0 && index <= u32::MAX as u64,
        "Invalid original interface index"
    );
    let adapter_name = row
        .get("InterfaceAlias")
        .and_then(|v| v.as_str())
        .context("Original route has no interface name")?
        .to_owned();
    let gateway: Ipv4Addr = row
        .get("NextHop")
        .and_then(|v| v.as_str())
        .context("Original route has no next hop")?
        .parse()?;
    let prefix = row
        .get("DestinationPrefix")
        .and_then(|v| v.as_str())
        .context("Original route has no prefix")?;
    Ok(PeerRoute {
        peer,
        interface: index.to_string(),
        adapter_name,
        gateway: (!gateway.is_unspecified()).then_some(gateway),
        existing_host: prefix == format!("{peer}/32"),
    })
}
#[cfg(target_os = "windows")]
fn peer_pin_commands(path: &PeerRoute) -> RouteCommands {
    let args = |action: &str| {
        vec![
            "interface".into(),
            "ipv4".into(),
            action.into(),
            "route".into(),
            format!("prefix={}/32", path.peer),
            format!("interface={}", path.interface),
            format!("nexthop={}", path.gateway.unwrap_or(Ipv4Addr::UNSPECIFIED)),
            "store=active".into(),
        ]
    };
    RouteCommands {
        add: CommandSpec::new(windows_system_binary("netsh.exe"), args("add")),
        delete: CommandSpec::new(windows_system_binary("netsh.exe"), args("delete")),
    }
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn snapshot_peer(_: Ipv4Addr) -> Result<PeerRoute> {
    bail!("Unsupported full tunnel routing platform")
}
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn peer_pin_commands(_: &PeerRoute) -> RouteCommands {
    unreachable!("Unsupported routing platform")
}

fn run_command(spec: &CommandSpec) -> Result<()> {
    let output = background_command(&spec.program)
        .args(&spec.args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("Running {}", spec.program))?;
    ensure!(
        output.status.success(),
        "Route command failed ({}): {}{}",
        output.status,
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn background_command(program: &str) -> Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let mut command = Command::new(program);
        // Hide netsh/PowerShell consoles, not the operating system's UAC consent.
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        command
    }
    #[cfg(not(windows))]
    Command::new(program)
}
fn execute_transaction(
    plans: &[RouteCommands],
    run: &mut impl FnMut(&CommandSpec) -> Result<()>,
) -> Result<Vec<CommandSpec>> {
    let mut undo = Vec::new();
    for plan in plans {
        if let Err(error) = run(&plan.add) {
            let mut failures = Vec::new();
            for command in undo.iter().rev() {
                if let Err(e) = run(command) {
                    failures.push(e.to_string());
                }
            }
            if !failures.is_empty() {
                return Err(
                    error.context(format!("Route rollback failures: {}", failures.join("; ")))
                );
            }
            return Err(error);
        }
        undo.push(plan.delete.clone());
    }
    Ok(undo)
}

/// Owns only routes successfully added by this connection. Existing routes are
/// never replaced. On an error, already-added routes are removed in reverse order.
pub struct RouteGuard {
    undo: Vec<CommandSpec>,
}
impl RouteGuard {
    /// `gateway` is the outer VPN server's IPv4 address, not the assigned VIP.
    pub fn install(interface: &str, routes: &[Ipv4Route], gateway: Ipv4Addr) -> Result<Self> {
        ensure!(
            cfg!(any(
                target_os = "macos",
                target_os = "linux",
                target_os = "windows"
            )),
            "Unsupported routing platform"
        );
        ensure!(
            is_admin(),
            "Administrator privileges are required to modify routes"
        );
        validate_interface(interface)?;
        let mut seen = HashSet::new();
        let mut plans = Vec::new();
        for route in routes {
            ensure!(
                !route.contains(gateway),
                "Route {route} includes the outer VPN gateway and would create a routing loop"
            );
            if seen.insert(*route) {
                plans.push(route_commands(interface, *route));
            }
        }
        Ok(Self {
            undo: execute_transaction(&plans, &mut run_command)?,
        })
    }
    /// Preserve every connected outer peer before installing two IPv4 /1
    /// overlays. Existing routes are never replaced or taken into ownership.
    pub fn install_full(interface: &str, peers: &[Ipv4Addr]) -> Result<Self> {
        ensure!(
            is_admin(),
            "Administrator privileges are required to modify routes"
        );
        validate_interface(interface)?;
        ensure!(
            !peers.is_empty(),
            "Full tunnel requires actual connected IPv4 peers"
        );
        let mut unique = HashSet::new();
        let mut snapshots = Vec::new();
        // Snapshot every path before any route is changed. A later lookup must
        // never observe one of our /1 overlays as the original outer path.
        for peer in peers {
            ensure!(
                !peer.is_unspecified()
                    && !peer.is_broadcast()
                    && !peer.is_multicast()
                    && !peer.is_loopback(),
                "Invalid outer IPv4 peer"
            );
            if unique.insert(*peer) {
                snapshots.push(snapshot_peer(*peer)?);
            }
        }
        let plans = full_route_plan(interface, &snapshots)?;
        Ok(Self {
            undo: execute_transaction(&plans, &mut run_command)?,
        })
    }

    /// Explicit cleanup allows the caller to surface OS failures before Drop retries.
    pub fn cleanup(&mut self) -> Result<()> {
        let mut failed = Vec::new();
        let mut errors = Vec::new();
        for command in self.undo.drain(..).rev() {
            if let Err(error) = run_command(&command) {
                errors.push(error.to_string());
                failed.push(command);
            }
        }
        failed.reverse();
        self.undo = failed;
        ensure!(
            errors.is_empty(),
            "Route cleanup failed: {}",
            errors.join("; ")
        );
        Ok(())
    }
}
impl Drop for RouteGuard {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("SSLRay: {error:#}");
        }
    }
}

/// Select whether macOS may use the host's existing Touch ID sudo policy.
/// Password always requests the normal system administrator dialog.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElevationMethod {
    Automatic,
    Password,
}

/// Launch the same executable with a native administrator prompt. This waits for
/// the privileged helper to exit; call from a launcher thread beside the IPC server.
/// The token authenticates the one-shot local IPC channel; VPN secrets are not args.
pub fn request_elevation(executable: &Path, port: u16, token: &str) -> Result<()> {
    ensure!(port != 0, "Invalid helper port");
    validate_helper_token(token)?;
    run_elevated(
        executable,
        &[
            "--helper".into(),
            "--parent-pid".into(),
            std::process::id().to_string().into(),
            "--port".into(),
            port.to_string().into(),
            "--token".into(),
            token.into(),
        ],
        ElevationMethod::Automatic,
    )
}

/// Unix helpers connect through a socket in a private directory. The app also
/// checks the accepted peer's UID before transmitting any VPN credentials.
#[cfg(unix)]
pub fn request_elevation_socket(executable: &Path, socket: &Path, token: &str) -> Result<()> {
    request_elevation_socket_with_method(executable, socket, token, ElevationMethod::Automatic)
}

/// A failed biometric attempt is terminal for this request. A password retry
/// must be an explicit new request, so an already-started helper is never relaunched.
#[cfg(unix)]
pub fn request_elevation_socket_with_method(
    executable: &Path,
    socket: &Path,
    token: &str,
    method: ElevationMethod,
) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;
    ensure!(socket.is_absolute(), "Helper socket path must be absolute");
    ensure!(
        socket.symlink_metadata()?.file_type().is_socket(),
        "Helper endpoint must be a Unix socket"
    );
    validate_helper_token(token)?;
    run_elevated(
        executable,
        &[
            "--helper".into(),
            "--parent-pid".into(),
            std::process::id().to_string().into(),
            "--socket".into(),
            socket.as_os_str().to_owned(),
            "--token".into(),
            token.into(),
        ],
        method,
    )
}

fn validate_helper_token(token: &str) -> Result<()> {
    ensure!(
        token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid helper token"
    );
    Ok(())
}

fn run_elevated(
    executable: &Path,
    arguments: &[std::ffi::OsString],
    method: ElevationMethod,
) -> Result<()> {
    let executable = executable
        .canonicalize()
        .context("Resolving helper executable")?;
    ensure!(executable.is_file(), "Helper executable is missing");
    #[cfg(target_os = "macos")]
    let (mut command, biometric) =
        macos_authorization::launch_command(&executable, arguments, method);
    #[cfg(not(target_os = "macos"))]
    let _ = method;
    #[cfg(target_os = "linux")]
    let mut command = {
        let pkexec = ["/usr/bin/pkexec", "/bin/pkexec"]
            .into_iter()
            .find(|p| Path::new(p).is_file())
            .context("Install polkit/pkexec to request administrator privileges")?;
        let mut c = Command::new(pkexec);
        c.arg(executable).args(arguments);
        c
    };
    #[cfg(target_os = "windows")]
    let mut command = {
        let executable = executable.to_str().context("Helper path is not Unicode")?;
        // This entry point only receives flags, a validated port and a hex nonce
        // on Windows. Escape literal quotes for the PowerShell string as well.
        let path = executable.replace('\'', "''");
        let args = arguments
            .iter()
            .map(|s| s.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
            .replace('\'', "''");
        let script = format!(
            "$ErrorActionPreference='Stop'; $p=Start-Process -FilePath '{path}' -ArgumentList '{args}' -Verb RunAs -PassThru -Wait; exit $p.ExitCode"
        );
        let mut c = background_command(&windows_system_binary(
            "WindowsPowerShell/v1.0/powershell.exe",
        ));
        c.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
        c
    };
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (executable, arguments);
        bail!("Administrator elevation is unavailable on this platform");
    }
    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        let output = command.stdin(Stdio::null()).output();
        #[cfg(target_os = "macos")]
        if biometric && !output.as_ref().is_ok_and(|output| output.status.success()) {
            // sudo's exit status cannot reliably distinguish a rejected prompt
            // from an error after the helper started. Never retry automatically.
            match output {
                Ok(output) => bail!(
                    "Administrator biometric authorization not completed ({}): {}",
                    output.status,
                    String::from_utf8_lossy(&output.stderr).trim(),
                ),
                Err(error) => {
                    return Err(error)
                        .context("Administrator biometric authorization not completed");
                }
            }
        }
        let output = output.context("Starting administrator authorization")?;
        if !output.status.success() {
            bail!(
                "Administrator authorization/helper failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }
}
#[cfg(target_os = "windows")]
fn windows_system_binary(name: &str) -> String {
    use std::os::windows::ffi::OsStringExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
    let mut buffer = [0u16; 32768];
    // SAFETY: the API receives a writable, adequately sized buffer.
    let count = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    let directory = if count > 0 && count < buffer.len() {
        std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer[..count]))
    } else {
        // A failed API must not fall back to a user-controlled PATH/SystemRoot.
        std::path::PathBuf::from("C:\\Windows\\System32")
    };
    directory.join(name).to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn routes_are_normalized_and_match_correct_prefix() {
        let route: Ipv4Route = "10.17.4.223/20".parse().unwrap();
        assert_eq!(route.to_string(), "10.17.0.0/20");
        assert!(route.contains("10.17.15.255".parse().unwrap()));
        assert!(!route.contains("10.17.16.0".parse().unwrap()));
        assert_eq!(
            "1.2.3.4/32".parse::<Ipv4Route>().unwrap().to_string(),
            "1.2.3.4/32"
        );
    }
    #[test]
    fn default_malformed_and_injected_routes_are_rejected() {
        for value in [
            "0.0.0.0/0",
            "1.2.3.4/33",
            "::1/128",
            "10.0.0.0",
            "10.0.0.0/8;id",
            "10.0.0.0/-1",
            "10.0.0.0/8/1",
        ] {
            assert!(value.parse::<Ipv4Route>().is_err(), "{value}");
        }
        for interface in ["", "utun0;id", "-eth0", "utun0\nfoo", "if name"] {
            assert!(validate_interface(interface).is_err(), "{interface}");
        }
    }
    #[test]
    fn partial_add_failure_rolls_back_only_successful_adds_in_reverse_order() {
        let plan = |name: &str| RouteCommands {
            add: CommandSpec::new("mock", [format!("add-{name}")]),
            delete: CommandSpec::new("mock", [format!("del-{name}")]),
        };
        let plans = [plan("a"), plan("b"), plan("c")];
        let mut calls = Vec::new();
        let result = execute_transaction(&plans, &mut |spec| {
            calls.push(spec.args[0].clone());
            if spec.args[0] == "add-c" {
                bail!("injected route conflict");
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(calls, ["add-a", "add-b", "add-c", "del-b", "del-a"]);
    }
    #[test]
    fn rollback_failures_are_reported_and_other_deletes_continue() {
        let plan = |name: &str| RouteCommands {
            add: CommandSpec::new("mock", [format!("add-{name}")]),
            delete: CommandSpec::new("mock", [format!("del-{name}")]),
        };
        let mut calls = Vec::new();
        let error = execute_transaction(&[plan("a"), plan("b"), plan("c")], &mut |spec| {
            calls.push(spec.args[0].clone());
            if matches!(spec.args[0].as_str(), "add-c" | "del-b") {
                bail!("injected failure");
            }
            Ok(())
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("rollback"));
        assert_eq!(calls.last().unwrap(), "del-a");
    }
    #[test]
    fn route_plan_does_not_use_a_shell_or_replace() {
        let plan = route_commands("utun42", "192.168.99.0/24".parse().unwrap());
        assert!(
            !["sh", "bash", "cmd.exe", "powershell.exe"].contains(
                &Path::new(&plan.add.program)
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
            )
        );
        assert!(plan.add.args.iter().any(|s| s == "add"));
        assert!(!plan.add.args.iter().any(|s| s == "replace"));
        assert!(plan.add.args.iter().any(|s| s.contains("192.168.99.0/24")));
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn mac_split_host_route_uses_host_key_for_both_add_and_delete() {
        let plan = route_commands("utun9", "172.22.110.30/32".parse().unwrap());
        assert_eq!(plan.add.program, "/sbin/route");
        assert_eq!(plan.delete.program, "/sbin/route");
        assert_eq!(
            plan.add.args,
            ["-n", "add", "-host", "172.22.110.30", "-interface", "utun9"]
        );
        assert_eq!(
            plan.delete.args,
            [
                "-n",
                "delete",
                "-host",
                "172.22.110.30",
                "-interface",
                "utun9"
            ]
        );
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn mac_network_and_full_tunnel_routes_keep_network_keys() {
        for cidr in ["172.22.110.0/24", "0.0.0.0/1", "128.0.0.0/1"] {
            let plan = route_commands("utun9", cidr.parse().unwrap());
            assert_eq!(
                plan.add.args,
                ["-n", "add", "-net", cidr, "-interface", "utun9"]
            );
            assert_eq!(
                plan.delete.args,
                ["-n", "delete", "-net", cidr, "-interface", "utun9"]
            );
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn mac_foreign_cloned_host_conflict_rolls_back_only_our_successful_routes() {
        let network = route_commands("utun9", "198.18.0.0/24".parse().unwrap());
        let host = route_commands("utun9", "172.22.110.30/32".parse().unwrap());
        // Simulate the kernel route keys. A network /32 would be a distinct
        // key and could incorrectly succeed beside this foreign HOST entry.
        let mut table = std::collections::HashMap::from([(
            ("-host".to_owned(), "172.22.110.30".to_owned()),
            "utun8:HOST,WASCLONED".to_owned(),
        )]);
        let original = table.clone();
        let mut calls = Vec::new();
        let result = execute_transaction(&[network.clone(), host.clone()], &mut |command| {
            calls.push(command.clone());
            let key = (command.args[2].clone(), command.args[3].clone());
            match command.args[1].as_str() {
                "add" => {
                    ensure!(
                        !table.contains_key(&key),
                        "Host route conflict: existing route belongs to another interface"
                    );
                    table.insert(key, "utun9".into());
                }
                "delete" => {
                    assert_eq!(table.get(&key).map(String::as_str), Some("utun9"));
                    table.remove(&key);
                }
                action => panic!("Unexpected route mutation: {action}"),
            }
            Ok(())
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Host route conflict")
        );
        assert_eq!(calls, [network.add, host.add, network.delete]);
        assert_eq!(
            table, original,
            "The foreign host route must remain untouched"
        );
    }
    fn outer_path(peer: &str, existing_host: bool) -> PeerRoute {
        PeerRoute {
            peer: peer.parse().unwrap(),
            interface: "en0".into(),
            adapter_name: "en0".into(),
            gateway: Some("192.168.1.1".parse().unwrap()),
            existing_host,
        }
    }
    #[test]
    fn full_tunnel_pins_all_outer_peers_before_overlays_without_owning_existing_hosts() {
        let paths = [
            outer_path("203.0.113.8", false),
            outer_path("198.51.100.9", true),
            outer_path("203.0.113.8", false),
        ];
        let plans = full_route_plan("utun42", &paths).unwrap();
        assert_eq!(plans.len(), 3);
        assert!(plans[0].add.args.join(" ").contains("203.0.113.8"));
        assert!(plans[1].add.args.iter().any(|s| s.contains("0.0.0.0/1")));
        assert!(plans[2].add.args.iter().any(|s| s.contains("128.0.0.0/1")));
        for plan in &plans {
            assert!(!plan.add.args.join(" ").contains("198.51.100.9"));
            assert!(!plan.delete.args.join(" ").contains("198.51.100.9"));
            assert!(
                !plan
                    .add
                    .args
                    .iter()
                    .any(|s| matches!(s.as_str(), "flush" | "replace" | "change"))
            );
        }
    }
    #[test]
    fn full_tunnel_last_overlay_failure_removes_first_overlay_then_own_pin() {
        let plans = full_route_plan(
            "utun42",
            &[
                outer_path("203.0.113.8", false),
                outer_path("198.51.100.9", true),
            ],
        )
        .unwrap();
        let mut calls = Vec::new();
        let result = execute_transaction(&plans, &mut |command| {
            calls.push(command.clone());
            if *command == plans[2].add {
                bail!("existing conflicting128/1route");
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(calls.len(), 5);
        assert_eq!(calls[3], plans[1].delete);
        assert_eq!(calls[4], plans[0].delete);
    }
    #[test]
    fn full_tunnel_rejects_missing_paths_and_self_capture_before_any_command() {
        assert!(full_route_plan("utun42", &[]).is_err());
        let mut path = outer_path("203.0.113.8", false);
        path.adapter_name = "utun42".into();
        assert!(full_route_plan("utun42", &[path]).is_err());
        let mut path = outer_path("203.0.113.8", false);
        path.interface = "en0;command".into();
        assert!(full_route_plan("utun42", &[path]).is_err());
    }
    #[test]
    fn mac_native_route_snapshot_distinguishes_default_and_existing_host() {
        let peer = "203.0.113.8".parse().unwrap();
        let default = "route to: 203.0.113.8\ndestination: default\nmask: default\ngateway: 192.168.1.1\ninterface: en0\nflags: <UP,GATEWAY,DONE,STATIC,GLOBAL>\n";
        let route = parse_mac_route(peer, default).unwrap();
        assert_eq!(route.interface, "en0");
        assert_eq!(route.gateway, Some("192.168.1.1".parse().unwrap()));
        assert!(!route.existing_host);
        let host = default
            .replace("destination: default", "destination: 203.0.113.8")
            .replace(
                "<UP,GATEWAY,DONE,STATIC,GLOBAL>",
                "<UP,GATEWAY,HOST,DONE,STATIC>",
            );
        assert!(parse_mac_route(peer, &host).unwrap().existing_host);
        assert!(parse_mac_route(peer, &host.replace("STATIC", "WASCLONED")).is_err());
        let scoped = host.replace("STATIC", "WASCLONED,IFSCOPE,IFREF");
        let scoped = parse_mac_route(peer, &scoped).unwrap();
        assert!(!scoped.existing_host);
        assert_eq!(full_route_plan("utun42", &[scoped]).unwrap().len(), 3);
        assert!(parse_mac_route(peer, &default.replace("en0", "en0;command")).is_err());
    }
    #[test]
    fn linux_fibmatch_route_snapshot_checks_prefix_device_and_policy_table() {
        let peer = "203.0.113.8".parse().unwrap();
        let default = r#"[{"dst":"default","gateway":"192.168.1.1","dev":"eth0","table":"main"}]"#;
        let path = parse_linux_route(peer, default).unwrap();
        assert_eq!(path.interface, "eth0");
        assert!(!path.existing_host);
        assert!(
            parse_linux_route(peer, &default.replace("default", "203.0.113.8/32"))
                .unwrap()
                .existing_host
        );
        assert!(parse_linux_route(peer, &default.replace("\"main\"", "100")).is_err());
        assert!(parse_linux_route(peer, r#"[{"type":"blackhole","dst":"default"}]"#).is_err());
        assert!(parse_linux_route(peer, "[]").is_err());
    }
    #[test]
    fn windows_route_snapshot_uses_index_with_space_containing_alias() {
        let peer = "203.0.113.8".parse().unwrap();
        let value = r#"{"InterfaceIndex":12,"InterfaceAlias":"Ethernet 2","DestinationPrefix":"0.0.0.0/0","NextHop":"192.168.1.1"}"#;
        let path = parse_windows_route(peer, value).unwrap();
        assert_eq!(path.interface, "12");
        assert_eq!(path.adapter_name, "Ethernet 2");
        assert_eq!(path.gateway, Some("192.168.1.1".parse().unwrap()));
        assert!(!path.existing_host);
        assert!(
            parse_windows_route(peer, &value.replace("0.0.0.0/0", "203.0.113.8/32"))
                .unwrap()
                .existing_host
        );
        assert!(parse_windows_route(peer, &value.replace(":12", ":0")).is_err());
    }
}
