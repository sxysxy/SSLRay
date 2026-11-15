//! Native Huawei network-extension authentication, distinct from browser login.
//! Login secrets are URL encoded inside verified TLS only and never logged.
use crate::{
    config::Profile,
    crypto::{self, TlsStream},
    legacy_http::LegacyAuth,
};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Write},
    time::Duration,
};
use zeroize::Zeroizing;

fn escape(value: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::new());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    out
}
fn stable_mac(profile: &Profile) -> String {
    let mut h = Sha256::digest(format!("{}|{}", profile.username, profile.host));
    h[0] = (h[0] | 2) & 0xfe;
    let s = hex::encode_upper(&h[..6]);
    format!("{}-{}-{}", &s[..4], &s[4..8], &s[8..])
}
fn read_body(stream: &mut TlsStream) -> Result<Zeroizing<Vec<u8>>> {
    let mut prefix = [0; 4];
    stream
        .read_exact(&mut prefix)
        .context("Reading native Huawei authentication prefix")?;
    if prefix == [0xf0; 4] {
        let mut status_bytes = [0; 4];
        stream
            .read_exact(&mut status_bytes)
            .context("Reading native Huawei authentication status")?;
        let status = i32::from_be_bytes(status_bytes);
        // SMS challenge records can carry a negative primary status. Read the
        // verified challenge field before deciding whether authentication failed.
        let mut body = Zeroizing::new(status_bytes.to_vec());
        stream
            .get_ref()
            .set_read_timeout(Some(Duration::from_millis(500)))?;
        while body.len() < 1020 {
            let mut chunk = [0; 1020];
            let take = 1020 - body.len();
            match stream.read(&mut chunk[..take]) {
                Ok(0) => break,
                Ok(n) => {
                    body.extend_from_slice(&chunk[..n]);
                    zeroize::Zeroize::zeroize(&mut chunk);
                }
                Err(error) if body.len() >= 84 => {
                    let _ = error;
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error)
                    if status < 0
                        && body.len() < 84
                        && matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) =>
                {
                    break;
                }
                Err(error) => {
                    return Err(error).context(format!(
                        "Reading native Huawei authentication record (status {status}; {} body bytes)",
                        body.len(),
                    ));
                }
            }
        }
        stream
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(15)))?;
        // Short refusals can include trailing bytes and leave TLS open. Only
        // after EOF/the bounded read deadline can they be distinguished from
        // complete negative-status SMS challenges; never retry the login.
        ensure!(
            status >= 0 || body.len() >= 84,
            "Native Huawei gateway rejected authentication (status {status}); no automatic retry"
        );
        ensure!(
            body.len() >= 84,
            "Truncated native Huawei authentication record (status {status}; {} body bytes)",
            body.len()
        );
        return Ok(body);
    }
    if prefix == *b"HTTP" {
        let mut reader = (&prefix[..]).chain(stream);
        let response = crate::legacy_http::read_response(&mut reader)?;
        ensure!(
            response.status == 200,
            "Native Huawei authentication returned HTTP {}",
            response.status
        );
        ensure!(
            (88..=1024).contains(&response.body.len()) && response.body[..4] == [0xf0; 4],
            "Unsupported native Huawei authentication response body ({} bytes)",
            response.body.len()
        );
        return Ok(Zeroizing::new(response.body[4..].to_vec()));
    }
    bail!("Unsupported native Huawei authentication framing")
}
fn u32_at(body: &[u8], at: usize) -> Result<u32> {
    let bytes = body
        .get(at..at.saturating_add(4))
        .context("Truncated native Huawei authentication field")?;
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| {
        anyhow::anyhow!("Invalid native Huawei authentication field length")
    })?))
}
fn sms_required(body: &[u8]) -> bool {
    u16::from_be_bytes([body[0x32], body[0x33]]) == 1
}
fn auth_fields(body: &[u8]) -> Result<LegacyAuth> {
    let user_id = u32_at(body, 0x28)?;
    ensure!(
        user_id != 0 && user_id != u32::MAX,
        "Native Huawei gateway did not authenticate the session"
    );
    let bytes = &body[0x54..body.len().min(0x54 + 64)];
    let length = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    ensure!(
        bytes.len() == 64 || length < bytes.len() || bytes.is_empty(),
        "Native authentication cookie was truncated"
    );
    let cookie = Zeroizing::new(
        std::str::from_utf8(&bytes[..length])
            .context("Invalid native session cookie encoding")?
            .to_owned(),
    );
    ensure!(
        cookie
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"\";\\,".contains(&b)),
        "Invalid native session cookie"
    );
    Ok(LegacyAuth {
        user_id,
        random_id: u32_at(body, 8)?,
        native_auth: true,
        vtid: u32_at(body, 4)?,
        cookie,
    })
}
fn finish_auth(body: &[u8]) -> Result<LegacyAuth> {
    let status = u32_at(body, 0)? as i32;
    ensure!(
        status >= 0 || matches!(status, -11 | -12),
        "Native Huawei gateway rejected authentication (status {status}); no automatic retry"
    );
    ensure!(
        u32_at(body, 0x18)? != 1,
        "Native Huawei gateway requires HostID device authentication; this is a separate, unsupported device challenge"
    );
    auth_fields(body)
}
fn request(
    profile: &Profile,
    stream: &mut TlsStream,
    path: &str,
    cookie: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    let cookie = Zeroizing::new(
        cookie
            .map(|c| format!("Cookie: {c}\r\n"))
            .unwrap_or_default(),
    );
    let request = Zeroizing::new(format!(
        "GET {path} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 6.0; NT 5.1; SV1; .NET CLR 2.0.50727)OS=Mac64\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: Keep-Alive\r\n{}\r\n",
        profile.host,
        profile.port,
        cookie.as_str()
    ));
    stream
        .write_all(request.as_bytes())
        .context("Sending native Huawei authentication request")?;
    stream.flush()?;
    read_body(stream)
}
pub fn authenticate_on(
    profile: &Profile,
    stream: &mut TlsStream,
    password: &str,
    mut challenge: impl FnMut(&str) -> Result<Zeroizing<String>>,
) -> Result<LegacyAuth> {
    profile.validate()?;
    ensure!(
        !profile.username.is_empty() && !password.is_empty() && password.len() <= 1024,
        "Invalid native VPN credentials"
    );
    let mac = crate::identity::socket_mac(stream.get_ref())
        .context("Reading gateway route interface MAC")?
        .unwrap_or_else(|| stable_mac(profile));
    let path = Zeroizing::new(format!(
        "/netextension/netextensionlogin.html?SelectLanguage=0&UserName={}&Password={}&MacAddress={}&SVN_Seco_AaA=1&",
        escape(&profile.username).as_str(),
        escape(password).as_str(),
        mac
    ));
    let body = request(profile, stream, &path, None)?;
    if !sms_required(&body) {
        return finish_auth(&body);
    }
    // Native UI maps exactly this u16 flag to SMS/DynamicToken. The legacy
    // request uses a new TLS connection; only the newer NEM v1 reuses its socket.
    let pending = auth_fields(&body)?;
    let result = (|| {
        let certificate = stream
            .ssl()
            .peer_certificate()
            .context("No native challenge peer certificate")?
            .to_der()?;
        let _ = stream.get_ref().shutdown(std::net::Shutdown::Both);
        let otp = challenge("sms")?;
        ensure!(
            !otp.is_empty() && otp.len() <= 31 && !otp.contains('\0'),
            "Enter a valid one-time verification code (maximum 31 bytes)"
        );
        let mut secondary = crypto::connect(profile)?;
        ensure!(
            secondary
                .ssl()
                .peer_certificate()
                .context("No native SMS peer certificate")?
                .to_der()?
                == certificate,
            "Gateway identity changed during native SMS authentication"
        );
        secondary
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(15)))?;
        secondary
            .get_ref()
            .set_write_timeout(Some(Duration::from_secs(15)))?;
        let path = Zeroizing::new(format!(
            "/checkrdsverificationcode.html?VTID={}&UserID={}&SessionID={}&SMSCode={}&SelectLanguage=2&",
            pending.vtid,
            pending.user_id,
            pending.random_id,
            escape(&otp).as_str()
        ));
        let cookie = Zeroizing::new(format!("SVN_SessionID={}", pending.cookie.as_str()));
        let body = request(profile, &mut secondary, &path, Some(&cookie))?;
        ensure!(
            !sms_required(&body),
            "Native Huawei gateway did not accept the verification code; no automatic retry"
        );
        let authenticated = finish_auth(&body)?;
        *stream = secondary;
        Ok(authenticated)
    })();
    if result.is_err() {
        let _ = logout_native(
            profile,
            pending.user_id,
            pending.random_id,
            pending.vtid,
            &pending.cookie,
        );
    }
    result.map_err(|error| {
        anyhow::anyhow!(
            "Native Huawei secondary authentication failed; no automatic retry: {error:#}"
        )
    })
}

pub use crate::legacy_http::logout_native;
