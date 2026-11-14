//! Authenticate the elevated end of the Windows helper's loopback connection.
//!
//! The nonce is deliberately not treated as a process identity: command-line
//! arguments can be observed by another local user. Before transmitting secrets,
//! bind the accepted connection's reverse TCP tuple to an OS-reported process,
//! then require an elevated token and the same canonical executable as the GUI.
//! The helper reciprocally binds the server endpoint to its launching GUI PID
//! and executable before it sends the nonce or accepts a privileged request.
//!
//! Uses documented Windows APIs, with signatures checked against windows-sys.
//! This Windows-only implementation has not been exercised on the macOS host.

use anyhow::{Context, Result, bail, ensure};
use std::{
    ffi::{OsString, c_void},
    io,
    mem::{offset_of, size_of},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream},
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    ptr,
};

const AF_INET: u32 = 2;
const TCP_TABLE_OWNER_PID_ALL: i32 = 5;
const TCP_ESTABLISHED: u32 = 5;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ELEVATION_CLASS: i32 = 20;
const STILL_ACTIVE: u32 = 259;
const MAX_TABLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TABLE_ATTEMPTS: usize = 4;
const MAX_IMAGE_PATH_UNITS: usize = 32_768;

type Handle = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy)]
struct TcpRow {
    state: u32,
    local_address: u32,
    local_port: u32,
    remote_address: u32,
    remote_port: u32,
    owning_pid: u32,
}

#[repr(C)]
struct TcpTable {
    count: u32,
    rows: [TcpRow; 1],
}

#[repr(C)]
struct TokenElevation {
    elevated: u32,
}

const ROWS_OFFSET: usize = offset_of!(TcpTable, rows);
const _: [(); 24] = [(); size_of::<TcpRow>()];
const _: [(); 4] = [(); ROWS_OFFSET];
const _: [(); 4] = [(); size_of::<TokenElevation>()];

#[link(name = "iphlpapi")]
unsafe extern "system" {
    #[link_name = "GetExtendedTcpTable"]
    fn get_extended_tcp_table(
        table: *mut c_void,
        size: *mut u32,
        order: i32,
        family: u32,
        table_class: i32,
        reserved: u32,
    ) -> u32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    #[link_name = "OpenProcess"]
    fn open_process(access: u32, inherit: i32, pid: u32) -> Handle;
    #[link_name = "CloseHandle"]
    fn close_handle(handle: Handle) -> i32;
    #[link_name = "GetExitCodeProcess"]
    fn get_exit_code_process(process: Handle, exit_code: *mut u32) -> i32;
    #[link_name = "QueryFullProcessImageNameW"]
    fn query_full_process_image_name(
        process: Handle,
        flags: u32,
        name: *mut u16,
        size: *mut u32,
    ) -> i32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    #[link_name = "OpenProcessToken"]
    fn open_process_token(process: Handle, access: u32, token: *mut Handle) -> i32;
    #[link_name = "GetTokenInformation"]
    fn get_token_information(
        token: Handle,
        class: i32,
        information: *mut c_void,
        size: u32,
        returned_size: *mut u32,
    ) -> i32;
}

struct OwnedHandle(Handle);

impl OwnedHandle {
    fn new(handle: Handle) -> Result<Self> {
        ensure!(
            !handle.is_null() && handle as isize != -1,
            "Windows returned an invalid process or token handle"
        );
        Ok(Self(handle))
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns exactly one valid, non-pseudo Windows handle.
        unsafe { close_handle(self.0) };
    }
}

/// Require an elevated SSLRay process at the other end of an accepted IPv4
/// loopback stream. Call this before sending the profile, password, or OTP.
///
/// Peer identity comes exclusively from the Windows TCP owner table; no PID or
/// executable name supplied over the connection is accepted. Any inspection
/// failure rejects the connection. The caller still authenticates its nonce.
pub fn verify_elevated_peer(stream: &TcpStream, expected_executable: &Path) -> Result<()> {
    verify_peer(stream, expected_executable, true, None)
}

/// Require that the helper's server endpoint is its launching SSLRay GUI.
///
/// `expected_pid` is passed by the launcher as a helper argument, rather than
/// accepted from a network message. Verify this before writing the nonce or
/// reading a request, including after a delayed UAC authorization. Elevation is
/// intentionally not required for the GUI; process identity, executable, and
/// lifetime are checked in both directions.
pub fn verify_server_peer(
    stream: &TcpStream,
    expected_executable: &Path,
    expected_pid: u32,
) -> Result<()> {
    ensure!(expected_pid != 0, "Missing launching GUI process identity");
    verify_peer(stream, expected_executable, false, Some(expected_pid))
}

fn verify_peer(
    stream: &TcpStream,
    expected_executable: &Path,
    require_elevated: bool,
    expected_pid: Option<u32>,
) -> Result<()> {
    let local = ipv4_loopback(stream.local_addr()?)?;
    let peer = ipv4_loopback(stream.peer_addr()?)?;
    let pid = tcp_owner(peer, local)?;
    ensure!(pid != 0, "SSLRay IPC endpoint has no owning process");
    if let Some(expected) = expected_pid {
        ensure!(
            pid == expected,
            "SSLRay IPC server is not the launching GUI process"
        );
    }

    // SAFETY: only limited query access is requested for the OS-reported PID.
    let raw_process = unsafe { open_process(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw_process.is_null() {
        return Err(io::Error::last_os_error()).context("Opening the SSLRay IPC peer process");
    }
    // Keep this process object alive throughout all checks to close a PID-reuse
    // window between opening its token/image and querying the TCP owner again.
    let process = OwnedHandle::new(raw_process)?;
    ensure_running(&process)?;
    if require_elevated {
        ensure_elevated(&process)?;
    }

    let actual = process_image(&process)?
        .canonicalize()
        .context("Canonicalizing the SSLRay IPC peer executable")?;
    let expected = expected_executable
        .canonicalize()
        .context("Canonicalizing the expected SSLRay executable")?;
    // Both paths come from filesystem canonicalization, including resolution of
    // reparse points. Exact equality avoids treating distinct files in a
    // case-sensitive Windows directory as an equal executable path.
    ensure!(
        actual == expected,
        "IPC peer executable does not match SSLRay"
    );

    // Inspect ownership again while retaining the process handle. A stale table
    // snapshot, a terminated/replaced process, or a changed socket fails closed.
    ensure!(
        tcp_owner(peer, local)? == pid,
        "SSLRay IPC TCP ownership changed during authentication"
    );
    ensure_running(&process)?;
    ensure!(
        stream.local_addr()? == SocketAddr::V4(local)
            && stream.peer_addr()? == SocketAddr::V4(peer),
        "SSLRay IPC socket endpoints changed during authentication"
    );
    Ok(())
}

fn ipv4_loopback(address: SocketAddr) -> Result<SocketAddrV4> {
    match address {
        SocketAddr::V4(address) if address.ip().is_loopback() && address.port() != 0 => Ok(address),
        _ => bail!("Windows helper identity requires an IPv4 loopback connection"),
    }
}

fn tcp_owner(local: SocketAddrV4, remote: SocketAddrV4) -> Result<u32> {
    let mut needed = 0u32;
    // SAFETY: a null output buffer requests the required allocation size.
    let status = unsafe {
        get_extended_tcp_table(
            ptr::null_mut(),
            &mut needed,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    ensure!(
        status == ERROR_INSUFFICIENT_BUFFER,
        "Cannot size the Windows TCP owner table: {}",
        io::Error::from_raw_os_error(status as i32)
    );

    for _ in 0..MAX_TABLE_ATTEMPTS {
        let requested = needed as usize;
        ensure!(
            (ROWS_OFFSET..=MAX_TABLE_BYTES).contains(&requested),
            "Windows TCP owner table exceeds the allocation limit"
        );
        // DWORD storage gives the OS structure its required alignment. A Vec<u8>
        // would not promise this even when the system allocator happens to do so.
        let mut storage = vec![0u32; requested.div_ceil(size_of::<u32>())];
        let allocated = storage.len() * size_of::<u32>();
        let mut returned = allocated as u32;
        // SAFETY: this aligned buffer has at least `returned` writable bytes.
        let status = unsafe {
            get_extended_tcp_table(
                storage.as_mut_ptr().cast(),
                &mut returned,
                0,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        if status == ERROR_INSUFFICIENT_BUFFER {
            needed = returned;
            continue;
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32))
                .context("Reading the Windows TCP owner table");
        }
        let bytes = returned as usize;
        ensure!(
            bytes >= ROWS_OFFSET && bytes <= allocated,
            "Windows returned an invalid TCP table size"
        );
        let count = storage[0] as usize;
        ensure!(
            count <= (bytes - ROWS_OFFSET) / size_of::<TcpRow>(),
            "Windows returned an invalid TCP table entry count"
        );
        let mut owner = None;
        for index in 0..count {
            let offset = ROWS_OFFSET + index * size_of::<TcpRow>();
            // SAFETY: the count and complete byte range were checked above;
            // read_unaligned additionally avoids assumptions about row padding.
            let row = unsafe {
                storage
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<TcpRow>()
                    .read_unaligned()
            };
            if row.state == TCP_ESTABLISHED && row_matches(&row, local, remote) {
                ensure!(owner.is_none(), "Ambiguous helper TCP endpoint ownership");
                owner = Some(row.owning_pid);
            }
        }
        return owner.context("No established Windows process owns the helper connection");
    }
    bail!("Windows TCP owner table kept changing; helper identity was not verified")
}

fn row_matches(row: &TcpRow, local: SocketAddrV4, remote: SocketAddrV4) -> bool {
    // Address/port members are stored in network byte order inside DWORDs.
    Ipv4Addr::from(row.local_address.to_ne_bytes()) == *local.ip()
        && u16::from_be(row.local_port as u16) == local.port()
        && Ipv4Addr::from(row.remote_address.to_ne_bytes()) == *remote.ip()
        && u16::from_be(row.remote_port as u16) == remote.port()
}

fn ensure_running(process: &OwnedHandle) -> Result<()> {
    let mut code = 0;
    // SAFETY: a held process handle with limited query access and valid output.
    if unsafe { get_exit_code_process(process.0, &mut code) } == 0 {
        return Err(io::Error::last_os_error())
            .context("Checking SSLRay IPC peer process lifetime");
    }
    ensure!(code == STILL_ACTIVE, "SSLRay IPC peer process has exited");
    Ok(())
}

fn ensure_elevated(process: &OwnedHandle) -> Result<()> {
    let mut raw_token = ptr::null_mut();
    // SAFETY: query-only token access on a held process handle and valid output.
    if unsafe { open_process_token(process.0, TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(io::Error::last_os_error()).context("Opening helper process token");
    }
    let token = OwnedHandle::new(raw_token)?;
    let mut elevation = TokenElevation { elevated: 0 };
    let mut returned = 0;
    // SAFETY: fixed-size TOKEN_ELEVATION output with its exact ABI length.
    if unsafe {
        get_token_information(
            token.0,
            TOKEN_ELEVATION_CLASS,
            ptr::from_mut(&mut elevation).cast(),
            size_of::<TokenElevation>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error()).context("Querying helper token elevation");
    }
    ensure!(
        returned as usize == size_of::<TokenElevation>() && elevation.elevated != 0,
        "Helper process is not elevated"
    );
    Ok(())
}

fn process_image(process: &OwnedHandle) -> Result<PathBuf> {
    let mut name = vec![0u16; MAX_IMAGE_PATH_UNITS];
    let mut length = name.len() as u32;
    // SAFETY: the buffer holds `length` UTF-16 code units and process is valid.
    if unsafe { query_full_process_image_name(process.0, 0, name.as_mut_ptr(), &mut length) } == 0 {
        return Err(io::Error::last_os_error()).context("Querying SSLRay IPC peer executable path");
    }
    ensure!(
        length > 0 && (length as usize) < name.len(),
        "Windows returned an invalid SSLRay IPC peer executable path"
    );
    Ok(OsString::from_wide(&name[..length as usize]).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_tuple_is_reversed_and_checks_both_ports() {
        let helper = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 51_234);
        let gui = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 44_321);
        let row = TcpRow {
            state: TCP_ESTABLISHED,
            local_address: u32::from_ne_bytes(helper.ip().octets()),
            local_port: helper.port().to_be() as u32,
            remote_address: u32::from_ne_bytes(gui.ip().octets()),
            remote_port: gui.port().to_be() as u32,
            owning_pid: 123,
        };
        assert!(row_matches(&row, helper, gui));
        assert!(!row_matches(&row, gui, helper));
        assert!(!row_matches(
            &row,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 51_235),
            gui
        ));
        assert!(!row_matches(
            &row,
            helper,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 44_322)
        ));
    }

    #[test]
    fn non_loopback_and_ipv6_are_rejected() {
        assert!(ipv4_loopback("192.0.2.1:1234".parse().unwrap()).is_err());
        assert!(ipv4_loopback("[::1]:1234".parse().unwrap()).is_err());
        assert!(ipv4_loopback("127.0.0.1:0".parse().unwrap()).is_err());
    }
}
