//! Bounded HTTP authentication for legacy Huawei NEM gateways. Redirects are
//! parsed locally; secrets are never forwarded to a redirected host.
use crate::config::Profile;
use anyhow::{Context, Result, bail, ensure};
use openssl::ssl::SslStream;
use std::{
    io::{Read, Write},
    net::TcpStream,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub struct LegacyAuth {
    pub user_id: u32,
    pub random_id: u32,
    pub vtid: u32,
    pub native_auth: bool,
    pub cookie: Zeroizing<String>,
}
pub(crate) struct Response {
    pub(crate) status: u16,
    headers: Zeroizing<String>,
    pub(crate) body: Zeroizing<Vec<u8>>,
}
pub(crate) fn read_response(stream: &mut impl Read) -> Result<Response> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut bytes = Zeroizing::new(Vec::new());
    while !bytes.ends_with(b"\r\n\r\n") {
        ensure!(
            bytes.len() < 65536 && Instant::now() < deadline,
            "HTTP authentication headers exceed bounds"
        );
        let mut byte = [0];
        stream
            .read_exact(&mut byte)
            .context("Reading legacy HTTP authentication response")?;
        bytes.push(byte[0]);
    }
    let headers =
        Zeroizing::new(String::from_utf8(bytes.to_vec()).context("Non-ASCII HTTP header")?);
    let status = headers
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .context("Missing HTTP status")?
        .parse()?;
    ensure!(
        headers.starts_with("HTTP/1."),
        "Unexpected legacy authentication framing"
    );
    let mut length = None;
    for line in headers.lines().skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                ensure!(length.is_none(), "Duplicate HTTP content length");
                length = Some(value.trim().parse::<usize>()?);
            }
            if name.eq_ignore_ascii_case("transfer-encoding") {
                bail!("Chunked authentication response is not supported");
            }
            if name.eq_ignore_ascii_case("content-encoding") {
                ensure!(
                    value.trim().eq_ignore_ascii_case("identity"),
                    "Compressed authentication response is not supported"
                );
            }
        }
    }
    let size = length.unwrap_or(0);
    ensure!(
        size <= 1024 * 1024,
        "HTTP authentication body exceeds limit"
    );
    let mut body = Zeroizing::new(vec![0; size]);
    let mut offset = 0;
    while offset < size {
        ensure!(
            Instant::now() < deadline,
            "HTTP authentication body timed out"
        );
        let n = stream.read(&mut body[offset..])?;
        ensure!(n > 0, "Truncated HTTP authentication body");
        offset += n;
    }
    Ok(Response {
        status,
        headers,
        body,
    })
}
fn header<'a>(response: &'a Response, name: &str) -> Option<&'a str> {
    response
        .headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
}
fn field<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    for (index, _) in text.match_indices(key) {
        if index > 0 && !b"?&; \r\n".contains(&text.as_bytes()[index - 1]) {
            continue;
        }
        return Some(
            text[index + key.len()..]
                .split(['&', ';', '\r', '\n', ' ', '"', '\'', '<', '>'])
                .next()
                .unwrap_or_default(),
        );
    }
    None
}
fn set_cookies(response: &Response) -> impl Iterator<Item = &str> {
    response
        .headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, value)| value.trim())
}
fn safe_cookie_octet(b: u8) -> bool {
    b.is_ascii_graphic() && !b"\";\\,".contains(&b)
}
fn cookie(response: &Response) -> Result<Zeroizing<String>> {
    let mut found = None;
    for line in set_cookies(response) {
        // Huawei combines two cookie names with '&' in older firmware.
        let primary = line.split(';').next().unwrap_or_default();
        for item in primary.split('&') {
            if let Some(value) = item.strip_prefix("SVN_SessionID=") {
                ensure!(
                    !value.is_empty() && value.len() <= 256 && value.bytes().all(safe_cookie_octet),
                    "Invalid gateway session cookie"
                );
                if let Some(previous) = found {
                    ensure!(previous == value, "Conflicting gateway session cookies");
                }
                found = Some(value);
            }
        }
    }
    Ok(Zeroizing::new(
        found
            .context("Gateway did not provide a session cookie")?
            .to_owned(),
    ))
}
fn user_id(response: &Response) -> Option<u32> {
    field(header(response, "Location").unwrap_or_default(), "UserID=")
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            set_cookies(response)
                .find_map(|line| field(line, "UserID=").and_then(|s| s.parse().ok()))
        })
}
fn form_escape(value: &str) -> Zeroizing<String> {
    let mut result = Zeroizing::new(String::new());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            result.push(b as char);
        } else {
            use std::fmt::Write;
            write!(&mut *result, "%{b:02X}").unwrap();
        }
    }
    result
}
fn post(profile: &Profile, stream: &mut SslStream<TcpStream>, body: &str) -> Result<Response> {
    let request = Zeroizing::new(format!(
        "POST /login.html HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: SSLRay/0.1\r\nAccept: */*\r\nAccept-Encoding: identity\r\nX-Client-OS: SSLRay\r\nConnection: Keep-Alive\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n{}",
        profile.host,
        profile.port,
        body.len(),
        body
    ));
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    read_response(stream)
}
pub fn authenticate_on(
    profile: &Profile,
    stream: &mut SslStream<TcpStream>,
    password: &str,
    mut challenge: impl FnMut(&str) -> Result<Zeroizing<String>>,
) -> Result<LegacyAuth> {
    profile.validate()?;
    // The gateway's supplied web form explicitly base64-encodes UTF-8 fields
    // before form encoding and marks this encoding with aaa=1.
    let user = Zeroizing::new(openssl::base64::encode_block(profile.username.as_bytes()));
    let password = Zeroizing::new(openssl::base64::encode_block(password.as_bytes()));
    let body = Zeroizing::new(format!(
        "UserName={}&Password={}&MacAddress=FFFF-FFFF-FFFF&SVN_Seco_AaA=1&SelectLanguage=0&VerificationCode=&VerificationCodeId=&aaa=1",
        form_escape(&user).as_str(),
        form_escape(&password).as_str()
    ));
    let mut response = post(profile, stream, &body)?;
    ensure!(
        matches!(response.status, 200 | 302 | 303),
        "Legacy HTTP authentication failed (HTTP {})",
        response.status
    );
    let location = header(&response, "Location").unwrap_or_default();
    if location.contains("/relogin.html") {
        let cause = field(location, "ReloginCause=")
            .filter(|v| v.bytes().all(|b| b.is_ascii_digit()))
            .unwrap_or("unknown");
        bail!("Gateway rejected authentication (legacy ReloginCause {cause}); no automatic retry");
    }
    if location.contains("/rdsverificationcode.html") {
        let vtid = field(location, "VTID=").context("Missing SMS challenge VTID")?;
        ensure!(
            !vtid.is_empty() && vtid.bytes().all(|b| b.is_ascii_digit()),
            "Invalid SMS challenge identifier"
        );
        let session_cookie = cookie(&response)?;
        let otp = challenge("sms")?;
        ensure!(
            !otp.is_empty() && otp.len() <= 31 && !otp.contains('\0'),
            "Temporary password must be 1..31 bytes"
        );
        let uid = user_id(&response).context("Missing SMS challenge UserID")?;
        let random = field(location, "RandomID=")
            .or_else(|| field(location, "SessionID="))
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        let identifiers = if random == 0 {
            String::new()
        } else {
            format!("UserID={uid}&SessionID={random}&")
        };
        let cookie_header = Zeroizing::new(if random == 0 {
            format!("UserID={uid}&SVN_SessionID={};", session_cookie.as_str())
        } else {
            format!("SVN_SessionID={}", session_cookie.as_str())
        });
        let request = Zeroizing::new(format!(
            "GET /checkrdsverificationcode.html?VTID={vtid}&{identifiers}SMSCode={}&SelectLanguage=2& HTTP/1.1\r\nHost: {}:{}\r\nCookie: {}\r\nAccept-Encoding: identity\r\nConnection: Keep-Alive\r\n\r\n",
            form_escape(&otp).as_str(),
            profile.host,
            profile.port,
            cookie_header.as_str()
        ));
        stream.write_all(request.as_bytes())?;
        stream.flush()?;
        response = read_response(stream)?;
    }
    ensure!(
        matches!(response.status, 200 | 302 | 303),
        "Legacy HTTP authentication failed (HTTP {})",
        response.status
    );
    let location = header(&response, "Location").unwrap_or_default();
    ensure!(
        !location.contains("/relogin.html"),
        "Gateway rejected temporary password"
    );
    let user_id = user_id(&response)
        .context("Gateway did not provide authenticated UserID; unsupported login challenge")?;
    ensure!(
        user_id != 0 && user_id != u32::MAX,
        "Gateway did not authenticate the user"
    );
    let session_cookie = cookie(&response)
        .map_err(|_| anyhow::anyhow!("Gateway did not provide an authenticated session cookie"))?;
    // Do not infer arbitrary HTML challenges or submit extra primary-password attempts.
    let _ = &response.body;
    let random_id = field(location, "RandomID=")
        .or_else(|| field(location, "SessionID="))
        .map(str::parse::<u32>)
        .transpose()
        .context("Invalid authenticated session identifier")?
        .unwrap_or(0);
    Ok(LegacyAuth {
        user_id,
        random_id,
        native_auth: false,
        vtid: field(location, "VTID=")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        cookie: session_cookie,
    })
}

/// Releases an authenticated legacy web session. No primary credentials are sent.
pub fn logout(profile: &Profile, user_id: u32, cookie: &str) -> Result<()> {
    profile.validate()?;
    ensure!(
        user_id != 0
            && !cookie.is_empty()
            && cookie.len() <= 256
            && cookie.bytes().all(safe_cookie_octet),
        "Invalid logout session"
    );
    let mut stream = crate::crypto::connect(profile)?;
    stream
        .get_ref()
        .set_read_timeout(Some(Duration::from_secs(3)))?;
    stream
        .get_ref()
        .set_write_timeout(Some(Duration::from_secs(3)))?;
    let request = Zeroizing::new(format!(
        "GET /logout.html?VTID=0&SelectLanguage=2& HTTP/1.1\r\nHost: {}:{}\r\nCookie: UserID={user_id}&SVN_SessionID={cookie};\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
        profile.host, profile.port
    ));
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let response = read_response(&mut stream)?;
    ensure!(
        matches!(response.status, 200 | 302 | 303),
        "Legacy logout failed (HTTP {})",
        response.status
    );
    Ok(())
}

pub fn logout_native(
    profile: &Profile,
    user_id: u32,
    random_id: u32,
    vtid: u32,
    cookie: &str,
) -> Result<()> {
    profile.validate()?;
    ensure!(
        user_id != 0 && cookie.len() <= 256 && cookie.bytes().all(safe_cookie_octet),
        "Invalid native logout session"
    );
    let mut stream = crate::crypto::connect(profile)?;
    stream
        .get_ref()
        .set_read_timeout(Some(Duration::from_secs(3)))?;
    stream
        .get_ref()
        .set_write_timeout(Some(Duration::from_secs(3)))?;
    let cookie_header = Zeroizing::new(if cookie.is_empty() {
        String::new()
    } else {
        format!("Cookie: SVN_SessionID={cookie}\r\n")
    });
    let request = Zeroizing::new(format!(
        "GET /logout.html?VTID={vtid}&UserID={user_id}&SessionID={random_id}&SelectLanguage=2& HTTP/1.1\r\nHost: {}:{}\r\n{}Accept-Encoding: identity\r\nConnection: close\r\n\r\n",
        profile.host,
        profile.port,
        cookie_header.as_str()
    ));
    stream.write_all(request.as_bytes())?;
    stream.flush()?;
    let response = read_response(&mut stream)?;
    ensure!(
        matches!(response.status, 200 | 302 | 303),
        "Native logout failed (HTTP {})",
        response.status
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_bounded_redirect_without_following_it() {
        let bytes=b"HTTP/1.1 302 Found\r\nLocation: /netextension/index.html?UserID=42&RandomID=314\r\nSet-Cookie: UserID=42&SVN_SessionID=abcdef; secure\r\nContent-Length: 0\r\n\r\n";
        let r = read_response(&mut &bytes[..]).unwrap();
        assert_eq!(
            field(header(&r, "Location").unwrap(), "UserID="),
            Some("42")
        );
        assert_eq!(cookie(&r).unwrap().as_str(), "abcdef");
    }
    #[test]
    fn refuses_ambiguous_or_unbounded_http() {
        for bytes in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 2000000\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            assert!(read_response(&mut &bytes[..]).is_err());
        }
    }
}
