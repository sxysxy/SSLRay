//! Native AnyConnect-compatible XML authentication and CSTP/TLS transport.
//! Independently implemented from the published OpenConnect protocol draft.
//! No host-scan scripts, browser automation, or external VPN process is executed.
use crate::{
    backend::{BackendConnection, PacketBackend},
    config::{Profile, TransportMode},
    crypto,
};
use anyhow::{Context, Result, bail, ensure};
use openssl::ssl::SslStream;
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{Ipv4Addr, Shutdown, TcpStream},
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_HTTP: usize = 1024 * 1024;
const MAGIC: &[u8; 4] = b"STF\x01";
const USER_AGENT: &str = "AnyConnect compatible SSLRay/0.1";

struct HttpResponse {
    status: u16,
    headers: Vec<(String, Zeroizing<String>)>,
    body: Zeroizing<Vec<u8>>,
}
impl HttpResponse {
    fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}
fn line(stream: &mut impl Read, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    loop {
        ensure!(out.len() < limit, "Cisco HTTP line exceeds limit");
        let mut b = [0];
        stream
            .read_exact(&mut b)
            .context("Reading Cisco HTTP response")?;
        out.push(b[0]);
        if out.ends_with(b"\r\n") {
            let end = out.len() - 2;
            out.truncate(end);
            return Ok(out);
        }
    }
}
fn read_http(stream: &mut impl Read, tunnel: bool) -> Result<HttpResponse> {
    let status_line = line(stream, 8192)?;
    let status_text = std::str::from_utf8(&status_line).context("Invalid Cisco HTTP status")?;
    ensure!(
        status_text.starts_with("HTTP/1."),
        "Invalid Cisco HTTP protocol"
    );
    let status = status_text
        .split_whitespace()
        .nth(1)
        .context("Missing Cisco HTTP status")?
        .parse()?;
    let mut headers = Vec::new();
    let mut size = status_line.len();
    loop {
        let l = line(stream, 16384)?;
        size += l.len() + 2;
        ensure!(size <= 65536, "Cisco HTTP headers exceed limit");
        if l.is_empty() {
            break;
        }
        let s = std::str::from_utf8(&l).context("Invalid Cisco HTTP header")?;
        let (n, v) = s.split_once(':').context("Malformed Cisco HTTP header")?;
        ensure!(
            !n.is_empty() && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "Invalid Cisco HTTP header name"
        );
        ensure!(
            v.bytes().all(|b| b == b'\t' || b >= 32 && b != 127),
            "Invalid Cisco HTTP header value"
        );
        headers.push((n.to_ascii_lowercase(), Zeroizing::new(v.trim().to_owned())));
    }
    let mut response = HttpResponse {
        status,
        headers,
        body: Zeroizing::new(Vec::new()),
    };
    if tunnel && status == 200 {
        return Ok(response);
    }
    ensure!(
        response
            .header("content-encoding")
            .is_none_or(|v| v.eq_ignore_ascii_case("identity")),
        "Unsupported Cisco HTTP content encoding"
    );
    let lengths: Vec<usize> = response
        .values("content-length")
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()?;
    ensure!(lengths.len() <= 1, "Duplicate Cisco HTTP content length");
    if let Some(encoding) = response.header("transfer-encoding") {
        ensure!(
            lengths.is_empty() && encoding.eq_ignore_ascii_case("chunked"),
            "Unsupported or ambiguous Cisco HTTP transfer encoding"
        );
        loop {
            let l = line(stream, 128)?;
            let s = std::str::from_utf8(&l)?;
            let count = usize::from_str_radix(s.split(';').next().unwrap_or("").trim(), 16)
                .context("Invalid Cisco chunk size")?;
            ensure!(
                count <= MAX_HTTP - response.body.len(),
                "Cisco HTTP body exceeds limit"
            );
            if count == 0 {
                let mut trailer_size = 0;
                loop {
                    let trailer = line(stream, 8192)?;
                    trailer_size += trailer.len() + 2;
                    ensure!(trailer_size <= 8192, "Cisco HTTP trailers exceed limit");
                    if trailer.is_empty() {
                        break;
                    }
                }
                break;
            }
            let start = response.body.len();
            response.body.resize(start + count, 0);
            stream.read_exact(&mut response.body[start..])?;
            let mut end = [0; 2];
            stream.read_exact(&mut end)?;
            ensure!(end == *b"\r\n", "Invalid Cisco HTTP chunk boundary");
        }
    } else if let Some(length) = lengths.first() {
        let length = *length;
        ensure!(length <= MAX_HTTP, "Cisco HTTP body exceeds limit");
        response.body.resize(length, 0);
        stream.read_exact(&mut response.body)?;
    } else {
        ensure!(
            status == 204
                || status == 302
                || status == 303
                || status == 301
                || status == 307
                || status == 308
                || status >= 400,
            "Cisco authentication response has no bounded body framing"
        );
    }
    Ok(response)
}
fn host(profile: &Profile) -> String {
    let h = if profile.host.contains(':') {
        format!("[{}]", profile.host)
    } else {
        profile.host.clone()
    };
    if profile.port == 443 {
        h
    } else {
        format!("{h}:{}", profile.port)
    }
}
fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "mac-intel"
    } else if cfg!(target_os = "windows") {
        "win"
    } else {
        "linux-64"
    }
}
fn escape(text: &str) -> Zeroizing<String> {
    let mut s = Zeroizing::new(String::new());
    for c in text.chars() {
        match c {
            '&' => s.push_str("&amp;"),
            '<' => s.push_str("&lt;"),
            '>' => s.push_str("&gt;"),
            '\"' => s.push_str("&quot;"),
            '\'' => s.push_str("&apos;"),
            c => s.push(c),
        }
    }
    s
}
fn query(kind: &str) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><config-auth client=\"vpn\" type=\"{kind}\" aggregate-auth-version=\"2\"><version who=\"vpn\">0.1</version><device-id>{}</device-id>",
        platform()
    ))
}
fn safe_path(profile: &Profile, value: &str) -> Result<String> {
    let path = if value.starts_with("https://") {
        let expected = format!("https://{}", host(profile));
        let rest = value
            .strip_prefix(&expected)
            .context("Cisco redirect changes gateway origin")?;
        ensure!(
            rest.starts_with('/'),
            "Cisco redirect changes gateway origin"
        );
        rest
    } else {
        value
    };
    ensure!(
        path.starts_with('/')
            && !path.starts_with("//")
            && path.len() <= 4096
            && path.bytes().all(|b| b.is_ascii_graphic() && b != b'\\'),
        "Unsupported Cisco authentication action/redirect"
    );
    Ok(path.to_owned())
}
struct HttpClient<'a> {
    profile: &'a Profile,
    stream: Option<SslStream<TcpStream>>,
    identity: Vec<u8>,
    cookies: BTreeMap<String, Zeroizing<String>>,
}
impl<'a> HttpClient<'a> {
    fn new(profile: &'a Profile) -> Result<Self> {
        let stream = crypto::connect(profile)?;
        let identity = stream
            .ssl()
            .peer_certificate()
            .context("Missing Cisco peer certificate")?
            .to_der()?;
        Ok(Self {
            profile,
            stream: Some(stream),
            identity,
            cookies: BTreeMap::new(),
        })
    }
    fn stream(&mut self) -> Result<&mut SslStream<TcpStream>> {
        if self.stream.is_none() {
            let s = crypto::connect(self.profile)?;
            ensure!(
                s.ssl()
                    .peer_certificate()
                    .context("Missing Cisco peer certificate")?
                    .to_der()?
                    == self.identity,
                "Cisco gateway identity changed between channels"
            );
            self.stream = Some(s);
        }
        Ok(self.stream.as_mut().unwrap())
    }
    fn cookie_header(&self) -> Zeroizing<String> {
        let mut s = Zeroizing::new(String::new());
        for (n, v) in &self.cookies {
            if !s.is_empty() {
                s.push_str("; ");
            }
            s.push_str(n);
            s.push('=');
            s.push_str(v);
        }
        s
    }
    fn remember(&mut self, response: &HttpResponse) -> Result<()> {
        for value in response.values("set-cookie") {
            let pair = value.split(';').next().unwrap_or("");
            let (n, v) = pair
                .split_once('=')
                .context("Invalid Cisco session cookie")?;
            ensure!(
                !n.is_empty()
                    && n.len() <= 128
                    && n.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                    && v.len() <= 16384
                    && v.bytes()
                        .all(|b| b.is_ascii_graphic() && !b";\"\\,".contains(&b)),
                "Invalid Cisco session cookie"
            );
            if v.is_empty() {
                self.cookies.remove(n);
            } else {
                self.cookies.insert(n.into(), Zeroizing::new(v.into()));
            }
            ensure!(self.cookies.len() <= 32, "Too many Cisco session cookies");
        }
        Ok(())
    }
    fn request(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&str>,
        extra: &str,
        tunnel: bool,
    ) -> Result<HttpResponse> {
        let cookies = self.cookie_header();
        let mut request = Zeroizing::new(format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nX-Transcend-Version: 1\r\nX-Aggregate-Auth: 1\r\nX-AnyConnect-Platform: {}\r\nConnection: Keep-Alive\r\n",
            host(self.profile),
            platform()
        ));
        if !cookies.is_empty() {
            request.push_str(&format!("Cookie: {}\r\n", cookies.as_str()));
        }
        request.push_str(extra);
        if let Some(b) = body {
            request.push_str(&format!(
                "Content-Type: application/xml; charset=utf-8\r\nContent-Length: {}\r\n",
                b.len()
            ));
        }
        request.push_str("\r\n");
        if let Some(b) = body {
            request.push_str(b);
        }
        let stream = self.stream()?;
        stream
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(15)))?;
        stream
            .get_ref()
            .set_write_timeout(Some(Duration::from_secs(10)))?;
        stream
            .write_all(request.as_bytes())
            .context("Sending Cisco HTTPS request")?;
        stream.flush()?;
        let response = read_http(stream, tunnel)?;
        self.remember(&response)?;
        if response
            .header("connection")
            .is_some_and(|v| v.eq_ignore_ascii_case("close"))
            && !(tunnel && response.status == 200)
        {
            self.stream = None;
        }
        Ok(response)
    }
}
fn xml_without_dtd(body: &[u8]) -> Result<Zeroizing<String>> {
    let text = std::str::from_utf8(body).context("Cisco authentication XML is not UTF-8")?;
    ensure!(
        !text.contains("<!ENTITY"),
        "Cisco XML entities are not supported"
    );
    let mut text = Zeroizing::new(text.to_owned());
    if let Some(start) = text.find("<!DOCTYPE") {
        let end = text[start..]
            .find('>')
            .context("Invalid Cisco XML doctype")?
            + start;
        ensure!(
            !text[start..end].contains('['),
            "Cisco internal XML DTD is not supported"
        );
        text.replace_range(start..=end, "");
    }
    Ok(text)
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_alphabetic()
                || b == b'_'
                || i > 0 && (b.is_ascii_digit() || b".-".contains(&b))
        })
}
fn authenticate(
    client: &mut HttpClient<'_>,
    password: &str,
    mut challenge: impl FnMut(&str) -> Result<Zeroizing<String>>,
) -> Result<()> {
    let mut body = query("init");
    body.push_str(&format!(
        "<group-access>https://{}/</group-access></config-auth>",
        escape(&host(client.profile)).as_str()
    ));
    let mut path = String::from("/");
    let mut password_sent = false;
    let mut otp_sent = false;
    let mut redirects = 0;
    for _ in 0..8 {
        let response = client.request("POST", &path, Some(&body), "", false)?;
        if matches!(response.status, 301 | 302 | 303 | 307 | 308) {
            ensure!(
                !password_sent && !otp_sent,
                "Cisco redirected after credential submission; refusing credential replay"
            );
            ensure!(redirects < 3, "Too many Cisco authentication redirects");
            redirects += 1;
            path = safe_path(
                client.profile,
                response
                    .header("location")
                    .context("Missing Cisco redirect location")?,
            )?;
            continue;
        }
        ensure!(
            response.status == 200,
            "Cisco authentication rejected (HTTP {}); no automatic retry",
            response.status
        );
        let text = xml_without_dtd(&response.body)?;
        let doc = roxmltree::Document::parse(&text).context("Invalid Cisco authentication XML")?;
        let root = doc.root_element();
        ensure!(
            root.tag_name().name() == "config-auth",
            "Unsupported Cisco authentication response"
        );
        if let Some(token) = root
            .children()
            .find(|n| n.has_tag_name("session-token"))
            .and_then(|n| n.text())
            .filter(|s| !s.is_empty())
        {
            ensure!(
                token.len() <= 16384
                    && token
                        .bytes()
                        .all(|b| b.is_ascii_graphic() && !b";\"\\,".contains(&b)),
                "Invalid Cisco session token"
            );
            client
                .cookies
                .insert("webvpn".into(), Zeroizing::new(token.into()));
        }
        let auth = root.children().find(|n| n.has_tag_name("auth"));
        let complete = root.attribute("type") == Some("complete")
            || auth.is_some_and(|a| a.attribute("id") == Some("success"));
        if complete {
            ensure!(
                client.cookies.get("webvpn").is_some_and(|v| !v.is_empty()),
                "Cisco authentication completed without a tunnel cookie"
            );
            return Ok(());
        }
        ensure!(
            !root.descendants().any(|n| n.has_tag_name("host-scan")
                || n.has_tag_name("sso-v2-login")
                || n.has_tag_name("sso-v2-login-final")),
            "Cisco gateway requires unsupported browser/host-scan authentication"
        );
        let auth = auth.context("Cisco authentication response has no form")?;
        let form = auth
            .children()
            .find(|n| n.has_tag_name("form"))
            .context("Cisco authentication response has no form")?;
        ensure!(
            form.attribute("method")
                .is_none_or(|method| method.eq_ignore_ascii_case("post")),
            "Cisco authentication form requires unsupported HTTP method"
        );
        if let Some(action) = form.attribute("action").filter(|s| !s.is_empty()) {
            path = safe_path(client.profile, action)?;
        }
        let explicit_challenge = auth.attribute("id") == Some("challenge");
        let mut reply = query("auth-reply");
        if let Some(opaque) = root.children().find(|n| n.has_tag_name("opaque")) {
            reply.push_str(&text[opaque.range()]);
        }
        reply.push_str("<auth>");
        let mut group = None;
        let mut fields = 0;
        let mut submitted_secret = false;
        let mut round_otp: Option<Zeroizing<String>> = None;
        for input in form.children().filter(|n| n.is_element()) {
            if !input.has_tag_name("input") && !input.has_tag_name("select") {
                continue;
            }
            if matches!(input.attribute("type"), Some("submit" | "reset")) {
                continue;
            }
            let name = input.attribute("name").unwrap_or("");
            ensure!(valid_name(name), "Unsupported Cisco form field name");
            ensure!(
                !matches!(
                    name,
                    "new_password" | "verify_password" | "new_pin" | "verify_pin" | "whichpin"
                ),
                "Cisco account password/PIN changes are not supported"
            );
            if input.has_tag_name("select") {
                let options: Vec<_> = input
                    .children()
                    .filter(|n| n.has_tag_name("option"))
                    .collect();
                let selected = options
                    .iter()
                    .find(|n| n.attribute("selected") == Some("true"))
                    .copied()
                    .or_else(|| (options.len() == 1).then(|| options[0]));
                let selected = selected
                    .context("Cisco authentication group requires an explicit selection")?;
                let value = selected
                    .attribute("value")
                    .or_else(|| selected.text())
                    .unwrap_or("");
                if name == "group_list" {
                    group = Some(value.to_owned());
                } else {
                    reply.push_str(&format!("<{name}>{}</{name}>", escape(value).as_str()));
                }
                continue;
            }
            if !input.has_tag_name("input") {
                continue;
            }
            let kind = input.attribute("type").unwrap_or("text");
            if matches!(kind, "submit" | "reset") {
                continue;
            }
            let value = if kind == "hidden" {
                Zeroizing::new(input.attribute("value").unwrap_or("").to_owned())
            } else if name == "username"
                || name == "user"
                || kind == "text" && name == "secondary_username"
            {
                Zeroizing::new(client.profile.username.clone())
            } else if kind == "password" || matches!(name, "otp" | "token" | "passcode" | "answer")
            {
                let secondary = explicit_challenge
                    || input.attribute("second-auth") == Some("1")
                    || matches!(
                        name,
                        "secondary_password"
                            | "password2"
                            | "otp"
                            | "token"
                            | "passcode"
                            | "answer"
                    );
                if secondary {
                    ensure!(
                        !otp_sent,
                        "Cisco verification code was rejected; no automatic retry"
                    );
                    if round_otp.is_none() {
                        let otp = challenge("Cisco/AnyConnect verification code")?;
                        ensure!(
                            !otp.is_empty() && otp.len() <= 256 && !otp.contains('\0'),
                            "Invalid Cisco verification code"
                        );
                        round_otp = Some(otp);
                    }
                    Zeroizing::new(round_otp.as_ref().unwrap().as_str().to_owned())
                } else {
                    ensure!(
                        !password_sent,
                        "Cisco credentials rejected or unsupported additional challenge; no automatic retry"
                    );
                    submitted_secret = true;
                    Zeroizing::new(password.to_owned())
                }
            } else {
                bail!("Unsupported Cisco authentication form field");
            };
            let name = if name == "answer" { "password" } else { name };
            reply.push_str(&format!("<{name}>{}</{name}>", escape(&value).as_str()));
            fields += 1;
            ensure!(fields <= 64, "Cisco form exceeds field limit");
        }
        ensure!(
            fields > 0 || group.is_some(),
            "Cisco authentication form has no supported fields"
        );
        reply.push_str("</auth>");
        if let Some(group) = group {
            reply.push_str(&format!(
                "<group-select>{}</group-select>",
                escape(&group).as_str()
            ));
        }
        reply.push_str("</config-auth>");
        password_sent |= submitted_secret;
        otp_sent |= round_otp.is_some();
        body = reply;
    }
    bail!("Cisco authentication exceeded round limit")
}

#[derive(Default)]
struct Decoder {
    bytes: Vec<u8>,
    since: Option<Instant>,
}
impl Drop for Decoder {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
impl Decoder {
    fn read(&mut self, stream: &mut impl Read) -> Result<Option<(u8, Zeroizing<Vec<u8>>)>> {
        loop {
            if self.bytes.len() >= 8 {
                ensure!(
                    &self.bytes[..4] == MAGIC && self.bytes[7] == 0,
                    "Invalid Cisco CSTP framing"
                );
                let length = u16::from_be_bytes([self.bytes[4], self.bytes[5]]) as usize;
                if self.bytes.len() == 8 + length {
                    let kind = self.bytes[6];
                    let body = Zeroizing::new(self.bytes[8..].to_vec());
                    self.bytes.zeroize();
                    self.bytes.clear();
                    self.since = None;
                    return Ok(Some((kind, body)));
                }
            }
            ensure!(
                self.since
                    .is_none_or(|t| t.elapsed() < Duration::from_secs(30)),
                "Cisco CSTP partial frame timed out"
            );
            let want = if self.bytes.len() < 8 {
                8 - self.bytes.len()
            } else {
                8 + u16::from_be_bytes([self.bytes[4], self.bytes[5]]) as usize - self.bytes.len()
            };
            let mut chunk = [0; 4096];
            let take = want.min(chunk.len());
            match stream.read(&mut chunk[..take]) {
                Ok(0) => bail!("Cisco CSTP tunnel closed"),
                Ok(n) => {
                    if self.bytes.is_empty() {
                        self.since = Some(Instant::now());
                    }
                    self.bytes.extend_from_slice(&chunk[..n]);
                    chunk[..n].zeroize();
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    return Ok(None);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e).context("Reading Cisco CSTP tunnel"),
            }
        }
    }
}
fn packet(stream: &mut impl Write, kind: u8, body: &[u8]) -> Result<()> {
    let size = u16::try_from(body.len()).context("Cisco CSTP packet exceeds limit")?;
    let mut out = Zeroizing::new(Vec::with_capacity(8 + body.len()));
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&size.to_be_bytes());
    out.extend_from_slice(&[kind, 0]);
    out.extend_from_slice(body);
    stream.write_all(&out)?;
    stream.flush()?;
    Ok(())
}
fn valid_ipv4(bytes: &[u8]) -> bool {
    bytes.len() >= 20
        && bytes[0] >> 4 == 4
        && (bytes[0] & 15) >= 5
        && (bytes[0] & 15) as usize * 4 <= bytes.len()
        && u16::from_be_bytes([bytes[2], bytes[3]]) as usize == bytes.len()
}
#[derive(Clone, Copy)]
struct Cidr {
    network: Ipv4Addr,
    prefix: u8,
}
fn cidr(value: &str) -> Result<Cidr> {
    let (ip, mask) = value
        .trim()
        .split_once('/')
        .context("Invalid Cisco IPv4 route")?;
    let ip: Ipv4Addr = ip.parse()?;
    let prefix = if mask.contains('.') {
        let mask: u32 = mask.parse::<Ipv4Addr>()?.into();
        let prefix = mask.leading_ones();
        ensure!(
            mask == u32::MAX.checked_shl(32 - prefix).unwrap_or(0),
            "Invalid Cisco route mask"
        );
        prefix
    } else {
        mask.parse::<u32>()?
    };
    ensure!(prefix <= 32, "Invalid Cisco route prefix");
    let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
    Ok(Cidr {
        network: Ipv4Addr::from(u32::from(ip) & mask),
        prefix: prefix as u8,
    })
}
fn subtract(route: Cidr, exclude: Cidr, out: &mut Vec<Cidr>) -> Result<()> {
    ensure!(
        out.len() < 4096,
        "Cisco split-route expansion exceeds limit"
    );
    let a = u32::from(route.network);
    let b = u32::from(exclude.network);
    let ap = route.prefix;
    let bp = exclude.prefix;
    let common = ap.min(bp);
    let mask = u32::MAX.checked_shl(32 - u32::from(common)).unwrap_or(0);
    if a & mask != b & mask {
        out.push(route);
    } else if ap < bp {
        let next = ap + 1;
        subtract(
            Cidr {
                network: Ipv4Addr::from(a),
                prefix: next,
            },
            exclude,
            out,
        )?;
        subtract(
            Cidr {
                network: Ipv4Addr::from(a | (1u32 << (32 - next))),
                prefix: next,
            },
            exclude,
            out,
        )?;
    }
    Ok(())
}
struct CiscoChannel {
    stream: SslStream<TcpStream>,
    decoder: Decoder,
    vip: Ipv4Addr,
    mtu: usize,
    last_rx: Instant,
    last_tx: Instant,
    last_dpd: Instant,
    keepalive: Duration,
    dpd: Duration,
    rekey_deadline: Option<Instant>,
    closed: bool,
}
impl CiscoChannel {
    fn send(&mut self, kind: u8, body: &[u8]) -> Result<()> {
        packet(&mut self.stream, kind, body)?;
        self.last_tx = Instant::now();
        Ok(())
    }
}
impl PacketBackend for CiscoChannel {
    fn send_packet(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            valid_ipv4(bytes) && bytes.len() <= self.mtu,
            "Cisco outgoing IPv4 packet is invalid or exceeds negotiated MTU"
        );
        ensure!(
            bytes[12..16] == self.vip.octets(),
            "Cisco outgoing IPv4 source differs from assigned address"
        );
        self.send(0, bytes)
    }
    fn read_packet(&mut self) -> Result<Option<Vec<u8>>> {
        for _ in 0..16 {
            let Some((kind, body)) = self.decoder.read(&mut self.stream)? else {
                return Ok(None);
            };
            self.last_rx = Instant::now();
            match kind {
                0 => {
                    // Some ocserv/Linux TUNs emit IPv6 neighbor discovery even
                    // when only IPv4 was negotiated. Do not forward it to the
                    // IPv4 interface; bound and discard a complete IPv6 packet.
                    if body.first().is_some_and(|b| b >> 4 == 6) {
                        ensure!(
                            body.len() >= 40
                                && usize::from(u16::from_be_bytes([body[4], body[5]])) + 40
                                    == body.len(),
                            "Cisco gateway sent malformed unsolicited IPv6"
                        );
                        continue;
                    }
                    ensure!(
                        valid_ipv4(&body),
                        "Cisco gateway sent unsupported or malformed IP packet (version {}, bytes {}, IPv4 declared length {})",
                        body.first().map_or(0, |b| b >> 4),
                        body.len(),
                        body.get(2..4)
                            .map_or(0, |s| u16::from_be_bytes([s[0], s[1]]))
                    );
                    return Ok(Some(body.to_vec()));
                }
                3 => {
                    ensure!(body.len() <= 256, "Cisco DPD payload exceeds limit");
                    self.send(4, &body)?;
                }
                4 | 7 => {}
                5 | 9 => bail!("Cisco gateway terminated the CSTP session"),
                8 => bail!("Cisco gateway sent unnegotiated compression"),
                _ => bail!("Unsupported Cisco CSTP packet type {kind}"),
            }
        }
        Ok(None)
    }
    fn set_read_budget(&self, budget: Duration) -> Result<()> {
        self.stream.get_ref().set_read_timeout(Some(budget))?;
        Ok(())
    }
    fn keepalive(&mut self) -> Result<()> {
        ensure!(
            self.rekey_deadline.is_none_or(|t| Instant::now() < t),
            "Cisco gateway requires session rekey; reconnect this session"
        );
        if !self.dpd.is_zero() {
            ensure!(
                self.last_rx.elapsed() < self.dpd.saturating_mul(3),
                "Cisco gateway stopped responding"
            );
            if self.last_rx.elapsed() >= self.dpd && self.last_dpd.elapsed() >= self.dpd {
                self.send(3, &[])?;
                self.last_dpd = Instant::now();
            }
        }
        if !self.keepalive.is_zero() && self.last_tx.elapsed() >= self.keepalive {
            self.send(7, &[])?;
        }
        Ok(())
    }
    fn outer_ipv4_addresses(&self) -> Result<Vec<Ipv4Addr>> {
        Ok(match self.stream.get_ref().peer_addr()?.ip() {
            std::net::IpAddr::V4(ip) => vec![ip],
            _ => vec![],
        })
    }
    fn disconnect(&mut self) {
        if !self.closed {
            let _ = self.send(5, b"\xb0Client disconnected");
        }
        self.close();
    }
    fn close(&mut self) {
        if !self.closed {
            self.closed = true;
            let _ = self.stream.get_ref().shutdown(Shutdown::Both);
        }
    }
}
impl Drop for CiscoChannel {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) fn connect(
    profile: &Profile,
    password: &str,
    challenge: impl FnMut(&str) -> Result<Zeroizing<String>>,
) -> Result<BackendConnection> {
    profile.validate()?;
    ensure!(
        profile.transport != TransportMode::Udp,
        "Cisco DTLS/UDP is not implemented; select TLS or Auto before authenticating"
    );
    ensure!(
        !profile.username.is_empty()
            && !password.is_empty()
            && password.len() <= 1024
            && !password.contains('\0'),
        "Enter valid Cisco credentials"
    );
    let mut client = HttpClient::new(profile)?;
    authenticate(&mut client, password, challenge)?;
    // A new CONNECT channel is independently verified and bound to the same leaf.
    client.stream = None;
    let extra = format!(
        "X-CSTP-Version: 1\r\nX-CSTP-Hostname: SSLRay\r\nX-CSTP-Protocol: Copyright (c) 2004 Cisco Systems, Inc.\r\nX-CSTP-MTU: {}\r\nX-CSTP-Base-MTU: 1500\r\nX-CSTP-Address-Type: IPv4\r\n",
        profile.mtu
    );
    let response = client.request("CONNECT", "/CSCOSSLC/tunnel", None, &extra, true)?;
    ensure!(
        response.status == 200,
        "Cisco CSTP CONNECT rejected (HTTP {})",
        response.status
    );
    let mut stream = client
        .stream
        .take()
        .context("Cisco tunnel socket missing")?;
    let configure = (|| -> Result<_> {
        ensure!(
            response
                .header("x-cstp-content-encoding")
                .is_none_or(|s| s.eq_ignore_ascii_case("identity")),
            "Cisco server requires unnegotiated compression"
        );
        let vip: Ipv4Addr = response
            .values("x-cstp-address")
            .find(|s| !s.contains(':'))
            .context("Cisco gateway did not assign IPv4")?
            .parse()?;
        ensure!(
            !vip.is_unspecified()
                && !vip.is_broadcast()
                && !vip.is_multicast()
                && !vip.is_loopback(),
            "Cisco gateway assigned unusable IPv4"
        );
        let mtu: usize = response
            .header("x-cstp-mtu")
            .context("Cisco gateway did not negotiate MTU")?
            .parse()?;
        ensure!((576..=65535).contains(&mtu), "Invalid Cisco negotiated MTU");
        let mtu = mtu.min(usize::from(profile.mtu));
        let mut routes = Vec::new();
        for value in response.values("x-cstp-split-include") {
            routes.push(cidr(value)?);
            ensure!(routes.len() <= 1024, "Too many Cisco routes");
        }
        if routes.is_empty() {
            routes.push(cidr("0.0.0.0/0")?);
        }
        for value in response.values("x-cstp-split-exclude") {
            let exclude = cidr(value)?;
            let mut next = Vec::new();
            for route in routes {
                subtract(route, exclude, &mut next)?;
            }
            routes = next;
        }
        let routes = routes
            .into_iter()
            .flat_map(|r| {
                if r.prefix == 0 {
                    vec!["0.0.0.0/1".to_owned(), "128.0.0.0/1".to_owned()]
                } else {
                    vec![format!("{}/{}", r.network, r.prefix)]
                }
            })
            .collect::<Vec<_>>();
        let mut dns = Vec::new();
        for value in response.values("x-cstp-dns").filter(|s| !s.contains(':')) {
            let ip: Ipv4Addr = value.parse()?;
            ensure!(
                !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast(),
                "Invalid Cisco DNS address"
            );
            if !dns.contains(&ip) {
                dns.push(ip);
            }
            ensure!(dns.len() <= 8, "Too many Cisco DNS servers");
        }
        let seconds = |name: &str, default: u64| -> Result<u64> {
            let n = response
                .header(name)
                .map(str::parse)
                .transpose()?
                .unwrap_or(default);
            ensure!(n <= 86400 * 30, "Cisco timer exceeds limit");
            Ok(n)
        };
        let keepalive = Duration::from_secs(seconds("x-cstp-keepalive", 30)?);
        let dpd = Duration::from_secs(seconds("x-cstp-dpd", 30)?);
        let rekey = seconds("x-cstp-rekey-time", 0)?;
        Ok((vip, mtu, routes, dns, keepalive, dpd, rekey))
    })();
    let (vip, mtu, routes, dns, keepalive, dpd, rekey) = match configure {
        Ok(c) => c,
        Err(e) => {
            let _ = packet(&mut stream, 5, b"\xb0Unsupported tunnel parameters");
            let _ = stream.get_ref().shutdown(Shutdown::Both);
            return Err(e);
        }
    };
    stream
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(50)))?;
    stream
        .get_ref()
        .set_write_timeout(Some(Duration::from_secs(3)))?;
    let cipher = stream
        .ssl()
        .current_cipher()
        .map(|c| format!("{} {}", stream.ssl().version_str(), c.name()))
        .unwrap_or_default();
    let now = Instant::now();
    Ok(BackendConnection {
        vip,
        routes,
        dns,
        cipher,
        transport: "TLS/CSTP (Cisco/AnyConnect)".into(),
        negotiated_mtu: Some(mtu as u16),
        channel: Box::new(CiscoChannel {
            stream,
            decoder: Decoder::default(),
            vip,
            mtu,
            last_rx: now,
            last_tx: now,
            last_dpd: now,
            keepalive,
            dpd,
            rekey_deadline: if rekey == 0 {
                None
            } else {
                Some(now + Duration::from_secs(rekey))
            },
            closed: false,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_cidr_and_split_exclusions_cover_only_allowed_addresses() {
        let full = cidr("0.0.0.0/0").unwrap();
        assert_eq!(full.prefix, 0);
        let mut allowed = Vec::new();
        subtract(full, cidr("10.0.0.0/255.0.0.0").unwrap(), &mut allowed).unwrap();
        assert_eq!(allowed.len(), 8);
        let contains = |ip: Ipv4Addr| {
            allowed.iter().any(|r| {
                let mask = u32::MAX.checked_shl(32 - u32::from(r.prefix)).unwrap_or(0);
                u32::from(ip) & mask == u32::from(r.network)
            })
        };
        assert!(!contains(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!contains(Ipv4Addr::new(10, 255, 255, 255)));
        assert!(contains(Ipv4Addr::new(9, 255, 255, 255)));
        assert!(contains(Ipv4Addr::new(11, 0, 0, 0)));
        let mut empty = Vec::new();
        subtract(full, full, &mut empty).unwrap();
        assert!(empty.is_empty());
        assert!(cidr("10.0.0.0/255.0.255.0").is_err());
    }

    #[test]
    fn chunked_http_is_bounded_and_rejects_ambiguous_framing() {
        let response = read_http(&mut &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n"[..], false).unwrap();
        assert_eq!(response.body.as_slice(), b"onetwo");
        assert!(
            read_http(
                &mut &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n"
                    [..],
                false
            )
            .is_err()
        );
        assert!(
            read_http(
                &mut &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100001\r\n"[..],
                false
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_entities_and_cross_origin_authentication_actions() {
        assert!(xml_without_dtd(b"<!DOCTYPE config-auth [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><config-auth>&x;</config-auth>").is_err());
        let p = Profile {
            host: "vpn.example".into(),
            port: 443,
            ..Profile::default()
        };
        assert!(safe_path(&p, "https://vpn.example.attacker.test/auth").is_err());
        assert!(safe_path(&p, "//attacker.test/auth").is_err());
        assert_eq!(safe_path(&p, "https://vpn.example/auth").unwrap(), "/auth");
    }
}
