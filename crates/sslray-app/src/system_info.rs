//! Read-only metadata for one explicitly named session interface. Callers must
//! obtain the name from the active SSLRay session, never a prefix/name guess.

use anyhow::Result;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdapterInfo {
    pub name: String,
    pub addresses: Vec<String>,
    pub is_up: bool,
    pub virtual_interface: bool,
    pub mtu: Option<u32>,
}

pub fn adapter(name: &str) -> Result<Option<AdapterInfo>> {
    anyhow::ensure!(
        !name.is_empty() && name.len() <= 1024 && !name.contains('\0'),
        "Invalid session interface name"
    );
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        unix_adapter(name)
    }
    #[cfg(windows)]
    {
        windows_adapter(name)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        anyhow::bail!("Network interface inventory is unavailable on this platform")
    }
}

fn virtual_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == "lo"
        || name == "lo0"
        || [
            "utun", "tun", "tap", "wintun", "ipsec", "ppp", "bridge", "br-", "veth", "virbr",
            "docker", "vmnet", "awdl", "llw",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn normalize(adapter: &mut AdapterInfo) {
    adapter.addresses.sort();
    adapter.addresses.dedup();
    adapter.virtual_interface |= virtual_name(&adapter.name);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn unix_adapter(target: &str) -> Result<Option<AdapterInfo>> {
    use std::{ffi::CStr, ptr};

    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            // SAFETY: getifaddrs owns this whole linked list until it is freed.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }

    let mut first = ptr::null_mut();
    // SAFETY: first is a writable output pointer; success transfers ownership.
    if unsafe { libc::getifaddrs(&mut first) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let list = Addresses(first);
    let mut current = list.0;
    let mut found = None::<AdapterInfo>;
    while !current.is_null() {
        // SAFETY: this entry and all its fields belong to the live getifaddrs list.
        let interface = unsafe { &*current };
        current = interface.ifa_next;
        if interface.ifa_name.is_null() {
            continue;
        }
        // SAFETY: getifaddrs supplies a NUL-terminated interface name.
        let name = unsafe { CStr::from_ptr(interface.ifa_name) }
            .to_string_lossy()
            .into_owned();
        if name != target {
            continue;
        }
        let adapter = found.get_or_insert_with(|| AdapterInfo {
            virtual_interface: virtual_name(&name),
            name,
            addresses: Vec::new(),
            is_up: false,
            mtu: None,
        });
        adapter.is_up |= interface.ifa_flags & libc::IFF_UP as u32 != 0;
        adapter.virtual_interface |= interface.ifa_flags & libc::IFF_LOOPBACK as u32 != 0;
        // SAFETY: address and netmask are either null or the family-specific
        // sockaddr objects supplied by getifaddrs for this entry.
        if let Some(address) =
            unsafe { unix_address(interface.ifa_addr, interface.ifa_netmask, &adapter.name) }
        {
            adapter.addresses.push(address);
        }
    }
    if let Some(adapter) = &mut found {
        adapter.mtu = unix_mtu(&adapter.name);
        normalize(adapter);
    }
    Ok(found)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe fn unix_address(
    address: *const libc::sockaddr,
    mask: *const libc::sockaddr,
    name: &str,
) -> Option<String> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    if address.is_null() {
        return None;
    }
    // SAFETY: caller guarantees an OS sockaddr of the declared family.
    let family = unsafe { (*address).sa_family as i32 };
    let (host, prefix) = match family {
        libc::AF_INET => {
            // SAFETY: family identifies a complete sockaddr_in.
            let address = unsafe { &*address.cast::<libc::sockaddr_in>() };
            let ip = Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes());
            // SAFETY: netmask, when non-null, is from the same ifaddrs entry.
            let prefix = unsafe { ipv4_mask(mask) };
            (ip.to_string(), prefix)
        }
        libc::AF_INET6 => {
            // SAFETY: family identifies a complete sockaddr_in6.
            let address = unsafe { &*address.cast::<libc::sockaddr_in6>() };
            let bytes = address.sin6_addr.s6_addr;
            #[cfg(target_os = "macos")]
            let bytes = {
                let mut bytes = bytes;
                // BSD can embed a link-local zone in the second 16-bit word.
                if bytes[0] == 0xfe && bytes[1] & 0xc0 == 0x80 {
                    bytes[2] = 0;
                    bytes[3] = 0;
                }
                bytes
            };
            let ip = Ipv6Addr::from(bytes);
            let host = if address.sin6_scope_id != 0 || ip.is_unicast_link_local() {
                format!("{ip}%{name}")
            } else {
                ip.to_string()
            };
            // SAFETY: netmask, when non-null, is from the same ifaddrs entry.
            let prefix = unsafe { ipv6_mask(mask) };
            (host, prefix)
        }
        _ => return None,
    };
    Some(match prefix {
        Some(prefix) => format!("{host}/{prefix}"),
        None => host,
    })
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe fn ipv4_mask(mask: *const libc::sockaddr) -> Option<u8> {
    #[cfg(target_os = "macos")]
    {
        // BSD permits shortened, zero-padded netmask sockaddrs. Do not create
        // a reference to a whole sockaddr_in when only sa_len bytes are valid.
        let bytes = unsafe {
            bsd_mask::<4>(
                mask,
                libc::AF_INET,
                std::mem::offset_of!(libc::sockaddr_in, sin_addr),
            )
        }?;
        mask_prefix(&bytes)
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: the caller guarantees a valid netmask sockaddr when non-null.
        if mask.is_null() || unsafe { (*mask).sa_family as i32 } != libc::AF_INET {
            return None;
        }
        // SAFETY: the family matches sockaddr_in.
        let mask = unsafe { &*mask.cast::<libc::sockaddr_in>() };
        mask_prefix(&mask.sin_addr.s_addr.to_ne_bytes())
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe fn ipv6_mask(mask: *const libc::sockaddr) -> Option<u8> {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: bsd_mask bounds each read to the OS-provided sa_len.
        let bytes = unsafe {
            bsd_mask::<16>(
                mask,
                libc::AF_INET6,
                std::mem::offset_of!(libc::sockaddr_in6, sin6_addr),
            )
        }?;
        mask_prefix(&bytes)
    }
    #[cfg(target_os = "linux")]
    {
        // SAFETY: the caller guarantees a valid netmask sockaddr when non-null.
        if mask.is_null() || unsafe { (*mask).sa_family as i32 } != libc::AF_INET6 {
            return None;
        }
        // SAFETY: the family matches sockaddr_in6.
        let mask = unsafe { &*mask.cast::<libc::sockaddr_in6>() };
        mask_prefix(&mask.sin6_addr.s6_addr)
    }
}

#[cfg(target_os = "macos")]
unsafe fn bsd_mask<const N: usize>(
    mask: *const libc::sockaddr,
    family: i32,
    offset: usize,
) -> Option<[u8; N]> {
    if mask.is_null() {
        return None;
    }
    // SAFETY: a non-null OS netmask has the BSD length/family header.
    let mask_family = unsafe { (*mask).sa_family as i32 };
    if mask_family != family && mask_family != libc::AF_UNSPEC {
        return None;
    }
    // SAFETY: only the header and bytes within sa_len are read.
    let length = unsafe { (*mask).sa_len as usize };
    let mut bytes = [0; N];
    let available = length.saturating_sub(offset).min(N);
    for (index, byte) in bytes.iter_mut().take(available).enumerate() {
        // SAFETY: offset + index is strictly smaller than sa_len.
        *byte = unsafe { *mask.cast::<u8>().add(offset + index) };
    }
    Some(bytes)
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn mask_prefix(mask: &[u8]) -> Option<u8> {
    let mut prefix = 0u8;
    let mut zero_seen = false;
    for byte in mask {
        for bit in (0..8).rev() {
            if byte & (1 << bit) == 0 {
                zero_seen = true;
            } else if zero_seen {
                return None;
            } else {
                prefix = prefix.checked_add(1)?;
            }
        }
    }
    Some(prefix)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn unix_mtu(name: &str) -> Option<u32> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    if name.len() >= libc::IFNAMSIZ || name.contains('\0') {
        return None;
    }
    // SAFETY: socket takes no pointers; OwnedFd closes a successful descriptor.
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if socket < 0 {
        return None;
    }
    // SAFETY: the descriptor is newly created and has a single owner.
    let socket = unsafe { OwnedFd::from_raw_fd(socket) };
    // SAFETY: zero initializes the ifreq union and provides NUL termination.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    for (destination, byte) in request.ifr_name.iter_mut().zip(name.bytes()) {
        *destination = byte as libc::c_char;
    }
    // SAFETY: SIOCGIFMTU only reads interface metadata into a full ifreq.
    if unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFMTU, &mut request) } != 0 {
        return None;
    }
    // SAFETY: successful SIOCGIFMTU initialized the ifru_mtu member.
    let mtu = unsafe { request.ifr_ifru.ifru_mtu };
    u32::try_from(mtu).ok().filter(|mtu| *mtu > 0)
}

#[cfg(windows)]
fn windows_adapter(target: &str) -> Result<Option<AdapterInfo>> {
    use anyhow::{Context, bail, ensure};
    use std::{
        io::Read,
        os::windows::process::CommandExt,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    // Fixed, read-only .NET calls work in inbox Windows PowerShell without
    // requiring optional NetAdapter modules or administrator privileges.
    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$target = $env:SSLRAY_SESSION_INTERFACE
$rows = @(foreach ($adapter in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
    if ($adapter.Name -cne $target) { continue }
    $properties = $adapter.GetIPProperties()
    $mtu = $null
    try { $mtu = [uint32]$properties.GetIPv4Properties().Mtu } catch {
        try { $mtu = [uint32]$properties.GetIPv6Properties().Mtu } catch {}
    }
    $addresses = @($properties.UnicastAddresses | ForEach-Object { '{0}/{1}' -f $_.Address.ToString(), $_.PrefixLength })
    [pscustomobject]@{
        name = $adapter.Name
        addresses = $addresses
        is_up = ($adapter.OperationalStatus -eq [System.Net.NetworkInformation.OperationalStatus]::Up)
        virtual_interface = (($adapter.NetworkInterfaceType -eq [System.Net.NetworkInformation.NetworkInterfaceType]::Tunnel) -or ($adapter.NetworkInterfaceType -eq [System.Net.NetworkInformation.NetworkInterfaceType]::Loopback) -or ($adapter.Description -match '(?i)wintun|wireguard|tap-windows|openvpn|virtual|vpn'))
        mtu = $mtu
    }
})
ConvertTo-Json -InputObject $rows -Compress -Depth 4
"#;
    const LIMIT: usize = 1024 * 1024;
    let mut child = Command::new(windows_powershell()?)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            SCRIPT,
        ])
        // The name is data, never interpolated into PowerShell source. Only
        // matching interface names proceed to address/MTU collection above.
        .env("SSLRAY_SESSION_INTERFACE", target)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .spawn()
        .context("Cannot start the Windows network interface query")?;
    let stdout = child
        .stdout
        .take()
        .context("Missing interface query output")?;
    let reader = thread::spawn(move || {
        let mut data = Vec::new();
        stdout.take((LIMIT + 1) as u64).read_to_end(&mut data)?;
        Ok::<_, std::io::Error>(data)
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                if let Err(error) = result {
                    return Err(error).context("Checking the Windows interface query");
                }
                bail!("Windows network interface query timed out");
            }
        }
    };
    let data = reader
        .join()
        .map_err(|_| anyhow::anyhow!("Interface query reader failed"))??;
    ensure!(status.success(), "Windows network interface query failed");
    ensure!(
        data.len() <= LIMIT,
        "Network interface query output exceeds the limit"
    );
    parse_windows(&data, target)
}

#[cfg(windows)]
fn windows_powershell() -> Result<std::path::PathBuf> {
    use anyhow::ensure;
    use std::os::windows::ffi::OsStringExt;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }
    let mut buffer = vec![0u16; 32768];
    // SAFETY: buffer is writable and its advertised capacity fits u32.
    let size = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    ensure!(
        size > 0 && (size as usize) < buffer.len(),
        "Cannot locate Windows system directory"
    );
    let system = std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer[..size as usize]));
    Ok(system.join("WindowsPowerShell/v1.0/powershell.exe"))
}

#[cfg(any(windows, test))]
fn parse_windows(data: &[u8], target: &str) -> Result<Option<AdapterInfo>> {
    use anyhow::{Context, ensure};
    let data = data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(data);
    let mut adapters: Vec<AdapterInfo> =
        serde_json::from_slice(data).context("Invalid Windows network interface inventory")?;
    ensure!(
        adapters.len() <= 1,
        "Unexpected interfaces in session query"
    );
    for adapter in &adapters {
        ensure!(
            adapter.name == target
                && adapter.name.len() <= 1024
                && adapter.addresses.len() <= 256
                && adapter.addresses.iter().all(|address| address.len() <= 160),
            "Invalid network interface inventory entry"
        );
    }
    let mut adapter = adapters.pop();
    if let Some(adapter) = &mut adapter {
        normalize(adapter);
    }
    Ok(adapter)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_must_be_contiguous() {
        assert_eq!(mask_prefix(&[255, 255, 255, 0]), Some(24));
        assert_eq!(mask_prefix(&[0; 4]), Some(0));
        assert_eq!(mask_prefix(&[255; 16]), Some(128));
        assert_eq!(mask_prefix(&[255, 0, 255, 0]), None);
    }

    #[test]
    fn windows_query_accepts_only_the_exact_session_interface() {
        let rows = br#"[
            {"name":"wintun-test","addresses":["192.0.2.2/32","192.0.2.2/32"],"is_up":false,"virtual_interface":false,"mtu":1400}
        ]"#;
        let adapter = parse_windows(rows, "wintun-test").unwrap().unwrap();
        assert_eq!(adapter.name, "wintun-test");
        assert_eq!(adapter.addresses.len(), 1);
        assert!(!adapter.is_up && adapter.virtual_interface);
        assert_eq!(adapter.mtu, Some(1400));
        assert!(parse_windows(rows, "wintun-other").is_err());
        assert!(parse_windows(rows, "WINTUN-TEST").is_err());
        assert!(parse_windows(b"[]", "wintun-test").unwrap().is_none());
        assert!(parse_windows(br#"[{"name":"Ethernet","addresses":[],"is_up":true,"virtual_interface":false,"mtu":1500},{"name":"wintun-test","addresses":[],"is_up":true,"virtual_interface":true,"mtu":1400}]"#, "wintun-test").is_err());
        assert!(parse_windows(br#"{"name":"not-an-array"}"#, "wintun-test").is_err());
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn native_query_reads_only_the_requested_name() {
        let name = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let interface = adapter(name).unwrap().unwrap();
        assert_eq!(interface.name, name);
        assert!(interface.is_up && interface.virtual_interface);
        assert!(
            interface
                .addresses
                .iter()
                .any(|address| address.starts_with("127.0.0.1"))
        );
        assert!(interface.mtu.is_some());
        assert!(adapter(&format!("{name}*")).unwrap().is_none());
        assert!(adapter("sslray-no-such-interface").unwrap().is_none());
        assert!(adapter("").is_err());
        assert!(adapter("bad\0name").is_err());
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn native_address_conversion_handles_byte_order_and_ipv6_scope() {
        // SAFETY: zero is a valid initial representation for sockaddr records.
        let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        address.sin_family = libc::AF_INET as libc::sa_family_t;
        #[cfg(target_os = "macos")]
        {
            address.sin_len = std::mem::size_of_val(&address) as u8;
        }
        address.sin_addr.s_addr = u32::from_ne_bytes([192, 0, 2, 10]);
        let mut mask = address;
        mask.sin_addr.s_addr = u32::from_ne_bytes([255, 255, 255, 0]);
        // SAFETY: the pointers refer to complete matching family records.
        let rendered = unsafe {
            unix_address(
                (&address as *const libc::sockaddr_in).cast(),
                (&mask as *const libc::sockaddr_in).cast(),
                "en0",
            )
        };
        assert_eq!(rendered.as_deref(), Some("192.0.2.10/24"));
        // SAFETY: zero initializes an IPv6 sockaddr before fields are set.
        let mut address: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        address.sin6_addr.s6_addr = "fe80::1".parse::<std::net::Ipv6Addr>().unwrap().octets();
        address.sin6_scope_id = 2;
        // SAFETY: address points to a valid IPv6 record and null mask is allowed.
        let rendered = unsafe {
            unix_address(
                (&address as *const libc::sockaddr_in6).cast(),
                std::ptr::null(),
                "en0",
            )
        };
        assert_eq!(rendered.as_deref(), Some("fe80::1%en0"));
    }
}
