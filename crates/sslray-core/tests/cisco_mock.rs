//! Loopback-only AnyConnect XML/CSTP interoperability and trust-boundary tests.
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod},
    x509::{X509, X509NameBuilder},
};
use sslray_core::{
    config::{Profile, TransportMode, VpnProtocol},
    gateway::Gateway,
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

fn identity() -> (SslAcceptor, String) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "SSLRay CSTP loopback")
        .unwrap();
    let name = name.build();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    cert.set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&key).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = cert.build();
    let pin = hex::encode(cert.digest(MessageDigest::sha256()).unwrap());
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    acceptor.set_private_key(&key).unwrap();
    acceptor.set_certificate(&cert).unwrap();
    (acceptor.build(), pin)
}
fn socket(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let socket = loop {
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "CSTP mock accept timed out");
                thread::sleep(Duration::from_millis(5));
            }
            Err(e) => panic!("CSTP mock accept failed: {e}"),
        }
    };
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
}
fn request(stream: &mut impl Read) -> (String, String) {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 65536);
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
    }
    let headers = String::from_utf8(bytes).unwrap();
    let count = headers
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .map(|s| s.parse::<usize>().unwrap())
        .unwrap_or(0);
    assert!(count < 65536);
    let mut body = vec![0; count];
    stream.read_exact(&mut body).unwrap();
    (headers, String::from_utf8(body).unwrap())
}
fn xml(stream: &mut impl Write, body: &str, extra: &str) {
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n{extra}\r\n{body}",
        body.len()
    )
    .unwrap();
    stream.flush().unwrap();
}
const FORM: &str = "<?xml version=\"1.0\"?><!DOCTYPE config-auth SYSTEM \"https://invalid.test/auth.dtd\"><config-auth type=\"auth-request\"><opaque><auth-id>fixture-context</auth-id></opaque><auth id=\"main\"><form method=\"post\" action=\"/auth\"><input type=\"text\" name=\"username\"/><input type=\"password\" name=\"password\"/></form></auth></config-auth>";
fn frame(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = b"STF\x01".to_vec();
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&[kind, 0]);
    out.extend_from_slice(body);
    out
}
fn read_frame(stream: &mut impl Read) -> (u8, Vec<u8>) {
    let mut head = [0; 8];
    stream.read_exact(&mut head).unwrap();
    assert_eq!(&head[..4], b"STF\x01");
    assert_eq!(head[7], 0);
    let mut body = vec![0; u16::from_be_bytes([head[4], head[5]]) as usize];
    stream.read_exact(&mut body).unwrap();
    (head[6], body)
}
fn ip() -> Vec<u8> {
    vec![
        0x45, 0, 0, 20, 0x12, 0x34, 0, 0, 64, 1, 0, 0, 10, 77, 0, 2, 10, 77, 0, 1,
    ]
}
fn profile(listener: &TcpListener, pin: String) -> Profile {
    Profile {
        protocol: VpnProtocol::Cisco,
        host: "127.0.0.1".into(),
        port: listener.local_addr().unwrap().port(),
        username: "loop<&user".into(),
        certificate_sha256: pin,
        transport: TransportMode::Tls,
        ..Profile::default()
    }
}
#[test]
fn xml_otp_cstp_routes_dpd_and_fragmented_data_round_trip() {
    let (acceptor, pin) = identity();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let profile = profile(&listener, pin);
    let server = thread::spawn(move || {
        let mut auth = acceptor.accept(socket(&listener)).unwrap();
        let (headers, body) = request(&mut auth);
        assert!(headers.starts_with("POST / HTTP/1.1"));
        assert!(body.contains("type=\"init\""));
        assert!(!body.contains("fixture-secret"));
        xml(&mut auth, FORM, "Set-Cookie: context=fixture; Secure\r\n");
        let (headers, body) = request(&mut auth);
        assert!(headers.starts_with("POST /auth HTTP/1.1"));
        assert!(headers.contains("Cookie: context=fixture"));
        assert!(body.contains("<username>loop&lt;&amp;user</username>"));
        assert!(body.contains("<password>fixture-secret&lt;&amp;</password>"));
        assert!(body.contains("<opaque><auth-id>fixture-context</auth-id></opaque>"));
        xml(
            &mut auth,
            "<config-auth type=\"auth-request\"><auth id=\"challenge\"><form><input type=\"password\" name=\"answer\"/></form></auth></config-auth>",
            "",
        );
        let (_, body) = request(&mut auth);
        assert!(body.contains("<password>123456</password>"));
        assert!(!body.contains("fixture-secret"));
        xml(
            &mut auth,
            "<config-auth type=\"complete\"><session-token>fixture-session</session-token><auth id=\"success\"/></config-auth>",
            "Connection: close\r\n",
        );
        let mut tunnel = acceptor.accept(socket(&listener)).unwrap();
        let (headers, body) = request(&mut tunnel);
        assert!(body.is_empty());
        assert!(headers.starts_with("CONNECT /CSCOSSLC/tunnel HTTP/1.1"));
        assert!(headers.contains("webvpn=fixture-session"));
        assert!(!headers.contains("X-DTLS"));
        tunnel.write_all(b"HTTP/1.1 200 CONNECTED\r\nX-CSTP-Address: 10.77.0.2\r\nX-CSTP-Netmask: 255.255.255.0\r\nX-CSTP-MTU: 1300\r\nX-CSTP-DNS: 10.77.0.1\r\nX-CSTP-Split-Include: 10.0.0.0/255.0.0.0\r\nX-CSTP-Split-Exclude: 10.128.0.0/255.128.0.0\r\nX-CSTP-Keepalive: 20\r\nX-CSTP-DPD: 30\r\n\r\n").unwrap();
        assert_eq!(read_frame(&mut tunnel), (0, ip()));
        // Linux TUN may generate IPv6 neighbor discovery despite IPv4-only
        // negotiation; it must be discarded without losing the IPv4 tunnel.
        let mut ipv6 = vec![0; 40];
        ipv6[0] = 0x60;
        ipv6[6] = 58;
        tunnel.write_all(&frame(0, &ipv6)).unwrap();
        tunnel.write_all(&frame(3, b"dpd-marker")).unwrap();
        assert_eq!(read_frame(&mut tunnel), (4, b"dpd-marker".to_vec()));
        let data = frame(0, &ip());
        tunnel.write_all(&data[..11]).unwrap();
        thread::sleep(Duration::from_millis(180));
        tunnel.write_all(&data[11..]).unwrap();
        let (kind, body) = read_frame(&mut tunnel);
        assert_eq!(kind, 5);
        assert_eq!(body[0], 0xb0);
    });
    let mut calls = 0;
    let mut gateway = Gateway::connect_with_challenge(&profile, "fixture-secret<&", |method| {
        assert_eq!(method, "Cisco/AnyConnect verification code");
        calls += 1;
        Ok(Zeroizing::new("123456".into()))
    })
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(gateway.vip.to_string(), "10.77.0.2");
    assert_eq!(gateway.negotiated_mtu, Some(1300));
    assert_eq!(gateway.routes, ["10.0.0.0/9"]);
    assert_eq!(gateway.dns[0].to_string(), "10.77.0.1");
    assert!(gateway.transport.contains("CSTP"));
    gateway.send_packet(&ip()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut timed_out = false;
    loop {
        assert!(Instant::now() < deadline, "CSTP data frame timed out");
        match gateway.read_packet().unwrap() {
            Some(packet) => {
                assert_eq!(packet, ip());
                break;
            }
            None => timed_out = true,
        }
    }
    assert!(timed_out, "Fragment did not cross a read timeout");
    gateway.disconnect();
    server.join().unwrap();
}
#[test]
fn pin_failure_prevents_any_authentication_bytes() {
    let (acceptor, pin) = identity();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut bad = pin.into_bytes();
    bad[0] = if bad[0] == b'0' { b'1' } else { b'0' };
    let profile = profile(&listener, String::from_utf8(bad).unwrap());
    let server = thread::spawn(move || {
        let mut tls = acceptor.accept(socket(&listener)).unwrap();
        let mut b = [0; 1];
        assert!(matches!(tls.read(&mut b), Ok(0) | Err(_)));
    });
    let error = Gateway::connect(&profile, "never-sent", None)
        .err()
        .unwrap();
    assert!(format!("{error:#}").contains("SHA-256 mismatch"));
    server.join().unwrap();
}
#[test]
fn rejects_repeated_password_without_callback_or_password_replay() {
    let (acceptor, pin) = identity();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let profile = profile(&listener, pin);
    let server = thread::spawn(move || {
        let mut tls = acceptor.accept(socket(&listener)).unwrap();
        request(&mut tls);
        xml(&mut tls, FORM, "");
        request(&mut tls);
        xml(&mut tls, FORM, "");
        let mut b = [0; 1];
        assert!(matches!(tls.read(&mut b), Ok(0) | Err(_)));
    });
    let mut called = false;
    let error = Gateway::connect_with_challenge(&profile, "private-secret", |_| {
        called = true;
        Ok(Zeroizing::new("000000".into()))
    })
    .err()
    .unwrap();
    assert!(!called);
    let message = format!("{error:#}");
    assert!(message.contains("no automatic retry"));
    assert!(!message.contains("private-secret"));
    server.join().unwrap();
}
#[test]
fn explicit_udp_is_rejected_before_opening_a_socket() {
    let profile = Profile {
        protocol: VpnProtocol::Cisco,
        host: "127.0.0.1".into(),
        port: 9,
        transport: TransportMode::Udp,
        ..Profile::default()
    };
    let error = Gateway::connect(&profile, "private-secret", None)
        .err()
        .unwrap();
    let text = format!("{error:#}");
    assert!(text.contains("TLS/CSTP"));
    assert!(!text.contains("Connection refused"));
}
