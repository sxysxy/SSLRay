//! Read the layer-2 address of the interface selected for a live VPN socket.
//! This performs local metadata queries only; it does not send network traffic.
use anyhow::Result;
use std::net::TcpStream;

/// Returns the actual selected local interface MAC as `XXXX-XXXX-XXXX`.
/// Interfaces without a six-byte link address (e.g. loopback/utun), unsupported
/// platforms and unresolvable interface mappings return `None` for caller fallback.
pub fn socket_mac(stream: &TcpStream) -> Result<Option<String>> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        unix_socket_mac(stream)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = stream;
        Ok(None)
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", test))]
fn format_mac(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 6 {
        return None;
    }
    Some(format!(
        "{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    ))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
struct InterfaceList(*mut libc::ifaddrs);
#[cfg(any(target_os = "macos", target_os = "linux"))]
impl Drop for InterfaceList {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this pointer is owned by one successful getifaddrs call.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn unix_socket_mac(stream: &TcpStream) -> Result<Option<String>> {
    use anyhow::Context;
    use std::ffi::CStr;
    let local = stream
        .local_addr()
        .context("Reading VPN socket local address")?;
    let mut head = std::ptr::null_mut();
    // SAFETY: `head` is writable and the returned list remains alive until guard Drop.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error()).context("Reading local network interfaces");
    }
    let list = InterfaceList(head);
    let mut cursor = list.0;
    let mut selected = None;
    while !cursor.is_null() {
        // SAFETY: cursor belongs to the allocated getifaddrs snapshot.
        let entry = unsafe { &*cursor };
        if !entry.ifa_name.is_null() && local_address_matches(entry.ifa_addr, local) {
            // SAFETY: getifaddrs provides NUL-terminated interface names.
            selected = Some(
                unsafe { CStr::from_ptr(entry.ifa_name) }
                    .to_bytes()
                    .to_vec(),
            );
            break;
        }
        cursor = entry.ifa_next;
    }
    let Some(selected) = selected else {
        return Ok(None);
    };
    cursor = list.0;
    while !cursor.is_null() {
        // SAFETY: cursor belongs to the same live snapshot.
        let entry = unsafe { &*cursor };
        if !entry.ifa_name.is_null()
            // SAFETY: this is a snapshot-owned NUL-terminated interface name.
            && unsafe { CStr::from_ptr(entry.ifa_name) }.to_bytes() == selected
            && let Some(mac) = link_address(entry.ifa_addr)
        {
            // An absent/zero/broadcast address is not an interface identity.
            if mac != [0; 6] && mac != [0xff; 6] {
                return Ok(format_mac(&mac));
            }
        }
        cursor = entry.ifa_next;
    }
    Ok(None)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn local_address_matches(address: *const libc::sockaddr, local: std::net::SocketAddr) -> bool {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    if address.is_null() {
        return false;
    }
    // SAFETY: each non-null getifaddrs address includes a sockaddr family header.
    let family = i32::from(unsafe { (*address).sa_family });
    match family {
        libc::AF_INET => {
            #[cfg(target_os = "macos")]
            // SAFETY: Darwin sockaddr always includes its length byte.
            if usize::from(unsafe { (*address).sa_len }) < std::mem::size_of::<libc::sockaddr_in>()
            {
                return false;
            }
            // SAFETY: getifaddrs AF_INET addresses use sockaddr_in. Darwin length
            // was checked above; Linux's API provides the corresponding fixed type.
            let ip = unsafe { (*(address.cast::<libc::sockaddr_in>())).sin_addr.s_addr };
            let ip = Ipv4Addr::from(u32::from_be(ip));
            match local.ip() {
                IpAddr::V4(local) => local == ip,
                IpAddr::V6(local) => local.to_ipv4_mapped() == Some(ip),
            }
        }
        libc::AF_INET6 => {
            #[cfg(target_os = "macos")]
            // SAFETY: the sockaddr header includes its reported allocation length.
            if usize::from(unsafe { (*address).sa_len }) < std::mem::size_of::<libc::sockaddr_in6>()
            {
                return false;
            }
            // SAFETY: getifaddrs AF_INET6 addresses use sockaddr_in6.
            let address = unsafe { &*address.cast::<libc::sockaddr_in6>() };
            let ip = Ipv6Addr::from(address.sin6_addr.s6_addr);
            match local {
                SocketAddr::V6(local) => {
                    *local.ip() == ip
                        && (local.scope_id() == 0 || local.scope_id() == address.sin6_scope_id)
                }
                _ => false,
            }
        }
        _ => false,
    }
}

#[cfg(target_os = "macos")]
fn link_address(address: *const libc::sockaddr) -> Option<[u8; 6]> {
    if address.is_null() {
        return None;
    }
    // SAFETY: a snapshot address always contains the sockaddr length/family header.
    if i32::from(unsafe { (*address).sa_family }) != libc::AF_LINK {
        return None;
    }
    let length = usize::from(unsafe { (*address).sa_len });
    let data_offset = std::mem::offset_of!(libc::sockaddr_dl, sdl_data);
    if length < data_offset {
        return None;
    }
    let link = address.cast::<libc::sockaddr_dl>();
    // SAFETY: nlen/alen are fixed header bytes before sdl_data, bounded above.
    let name_len = usize::from(unsafe { (*link).sdl_nlen });
    let mac_len = usize::from(unsafe { (*link).sdl_alen });
    if mac_len != 6 {
        return None;
    }
    let start = data_offset.checked_add(name_len)?;
    let end = start.checked_add(mac_len)?;
    if end > length {
        return None;
    }
    // SAFETY: sdl_len bounds the variable sockaddr_dl allocation. MAC bytes begin
    // after its interface name; no fixed sdl_data array indexing crosses bounds.
    let bytes = unsafe { std::slice::from_raw_parts(address.cast::<u8>().add(start), mac_len) };
    bytes.try_into().ok()
}
#[cfg(target_os = "linux")]
fn link_address(address: *const libc::sockaddr) -> Option<[u8; 6]> {
    if address.is_null() {
        return None;
    }
    // SAFETY: snapshot addresses carry a valid family field.
    if i32::from(unsafe { (*address).sa_family }) != libc::AF_PACKET {
        return None;
    }
    // SAFETY: getifaddrs provides sockaddr_ll for AF_PACKET addresses on Linux.
    let link = unsafe { &*address.cast::<libc::sockaddr_ll>() };
    let length = usize::from(link.sll_halen);
    if length != 6 || length > link.sll_addr.len() {
        return None;
    }
    link.sll_addr[..length].try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formats_only_six_bytes_in_vendor_mac_notation() {
        assert_eq!(
            format_mac(&[0x02, 0x1a, 0xb3, 0, 0xff, 9]).as_deref(),
            Some("021A-B300-FF09")
        );
        assert_eq!(
            format_mac(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]).as_deref(),
            Some("0011-2233-4455")
        );
        assert!(format_mac(&[]).is_none());
        assert!(format_mac(&[0; 5]).is_none());
        assert!(format_mac(&[0; 7]).is_none());
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_link_address_checks_variable_name_and_allocation_bounds() {
        // SAFETY: sockaddr_dl is a plain C integer/byte structure; all-zero is valid.
        let mut address: libc::sockaddr_dl = unsafe { std::mem::zeroed() };
        address.sdl_family = libc::AF_LINK as u8;
        address.sdl_len = std::mem::size_of_val(&address) as u8;
        address.sdl_nlen = 3;
        address.sdl_alen = 6;
        let bytes = [b'e', b'n', b'0', 0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        for (slot, value) in address.sdl_data.iter_mut().zip(bytes) {
            *slot = value as libc::c_char;
        }
        let read = |address: &libc::sockaddr_dl| {
            link_address((address as *const libc::sockaddr_dl).cast())
        };
        assert_eq!(read(&address), Some([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]));
        address.sdl_len = 16;
        assert!(read(&address).is_none());
        address.sdl_len = std::mem::size_of_val(&address) as u8;
        address.sdl_nlen = 200;
        assert!(read(&address).is_none());
        address.sdl_nlen = 3;
        address.sdl_alen = 7;
        assert!(read(&address).is_none());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_link_address_requires_six_bytes_inside_sockaddr_ll() {
        // SAFETY: sockaddr_ll is a plain C integer/byte structure.
        let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        address.sll_family = libc::AF_PACKET as u16;
        address.sll_halen = 6;
        address.sll_addr[..6].copy_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let read = |address: &libc::sockaddr_ll| {
            link_address((address as *const libc::sockaddr_ll).cast())
        };
        assert_eq!(read(&address), Some([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]));
        address.sll_halen = 9;
        assert!(read(&address).is_none());
    }
}
