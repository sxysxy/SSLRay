//! Local TLS/NEM interoperability checks. No credentials, interfaces or routes
//! from the developer's machine are used; all peer traffic remains on loopback.
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
use sslray_core::{config::Profile, gateway::Gateway};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

fn test_identity() -> (SslAcceptor, String) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "SSLRay loopback test")
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
    acceptor.check_private_key().unwrap();
    (acceptor.build(), pin)
}
fn bounded_socket(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "Expected local TLS connection did not arrive"
                );
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("Local TLS accept failed: {error}"),
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
fn read_wire(stream: &mut impl Read, expected: u8) -> Vec<u8> {
    let mut header = [0; 8];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(&header[..5], &[0xc1, 0x92, 0xa4, 0xd6, 1]);
    assert_eq!(header[5], expected);
    let mut payload = vec![0; u16::from_be_bytes([header[6], header[7]]) as usize];
    stream.read_exact(&mut payload).unwrap();
    payload
}
fn wire(command: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0xc1, 0x92, 0xa4, 0xd6, 1, command];
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}
fn ipv4_packet() -> Vec<u8> {
    // Minimal IPv4 header. NEM transports the existing packet unchanged.
    vec![
        0x45, 0, 0, 20, 0x12, 0x34, 0, 0, 64, 1, 0, 0, 10, 77, 0, 2, 10, 77, 0, 1,
    ]
}
fn spawn_gateway(sms: bool) -> (Profile, JoinHandle<()>) {
    let (acceptor, pin) = test_identity();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let profile = Profile {
        host: "127.0.0.1".into(),
        port: listener.local_addr().unwrap().port(),
        username: "loopback-user".into(),
        certificate_sha256: pin,
        ..Profile::default()
    };
    let server = thread::spawn(move || {
        let mut control = acceptor.accept(bounded_socket(&listener)).unwrap();
        let mut first = [0u8; 340];
        control.read_exact(&mut first).unwrap();
        assert_eq!(
            &first[..16],
            &[
                0xfe, 0xfc, 0xef, 0xbe, 0xc1, 0x92, 0xa4, 0xd6, 0, 0, 0, 0, 0, 0x1d, 1, 0x44
            ]
        );
        assert_eq!(&first[80..89], b"127.0.0.1");
        control.write_all(&wire(0, &[0; 4])).unwrap();
        let auth = read_wire(&mut control, 1);
        assert!(
            auth.windows(b"loopback-user\0".len())
                .any(|v| v == b"loopback-user\0")
        );
        assert!(
            auth.windows(b"fixture%26password\0".len())
                .any(|v| v == b"fixture%26password\0")
        );
        if sms {
            // Captured protocol layout: status=1, reserved=0, method TLV=1.
            control
                .write_all(&wire(1, &[0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 0, 1, 1]))
                .unwrap();
            let otp = read_wire(&mut control, 2);
            assert_eq!(otp.len(), 33);
            assert_eq!(&otp[..7], b"\x01123456");
            assert!(otp[7..].iter().all(|v| *v == 0));
        }
        let token = [0x42u8; 32];
        let mut success = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 32];
        success.extend_from_slice(&token);
        control.write_all(&wire(1, &success)).unwrap();
        assert_eq!(read_wire(&mut control, 3), token);
        // Assigned address plus one split route, encoded as 5-byte IPv4/prefix.
        control
            .write_all(&wire(
                3,
                &[
                    0, 0, 0, 0, 0, 1, 0, 5, 10, 77, 0, 2, 32, 0, 6, 0, 5, 10, 77, 0, 0, 24,
                ],
            ))
            .unwrap();
        let mut data = acceptor.accept(bounded_socket(&listener)).unwrap();
        assert_eq!(read_wire(&mut data, 0x64), token);
        data.write_all(&wire(0x64, &[0])).unwrap();
        let payload = read_wire(&mut data, 0x66);
        assert_eq!(&payload[..8], &[0; 8]);
        assert_eq!(&payload[8..], ipv4_packet());
        data.write_all(&wire(0x65, &[])).unwrap();
        let response = wire(0x66, &payload);
        data.write_all(&response[..10]).unwrap();
        // Cross the client's 100 ms read timeout with a partial frame body.
        thread::sleep(Duration::from_millis(180));
        data.write_all(&response[10..]).unwrap();
        // Keep the control peer alive until the client finishes reading.
        thread::sleep(Duration::from_millis(200));
    });
    (profile, server)
}
fn round_trip(mut gateway: Gateway) {
    assert_eq!(gateway.vip.to_string(), "10.77.0.2");
    assert_eq!(gateway.routes, ["10.77.0.0/24"]);
    gateway.send_packet(&ipv4_packet()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        assert!(Instant::now() < deadline, "Local data frame timed out");
        if let Some(packet) = gateway.read_packet().unwrap() {
            assert_eq!(packet, ipv4_packet());
            break;
        }
    }
    gateway.disconnect();
}

#[test]
fn authenticates_two_tls_channels_and_preserves_packet_across_timeout() {
    let (profile, server) = spawn_gateway(false);
    let gateway = Gateway::connect(&profile, "fixture&password", None).unwrap();
    round_trip(gateway);
    server.join().unwrap();
}
#[test]
fn requests_sms_only_after_live_gateway_challenge_then_opens_data_channel() {
    let (profile, server) = spawn_gateway(true);
    let mut challenged = false;
    let gateway = Gateway::connect_with_challenge(&profile, "fixture&password", |method| {
        assert_eq!(method, "sms");
        assert!(!challenged, "OTP callback was replayed");
        challenged = true;
        Ok(Zeroizing::new("123456".into()))
    })
    .unwrap();
    assert!(challenged);
    round_trip(gateway);
    server.join().unwrap();
}
#[test]
fn wrong_certificate_pin_prevents_all_nem_application_data() {
    let (acceptor, actual_pin) = test_identity();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut bad_pin = actual_pin.into_bytes();
    bad_pin[0] = if bad_pin[0] == b'0' { b'1' } else { b'0' };
    let profile = Profile {
        host: "127.0.0.1".into(),
        port: listener.local_addr().unwrap().port(),
        username: "loopback-user".into(),
        certificate_sha256: String::from_utf8(bad_pin).unwrap(),
        ..Profile::default()
    };
    let server = thread::spawn(move || {
        let mut tls = acceptor.accept(bounded_socket(&listener)).unwrap();
        let mut data = [0u8; 512];
        assert!(
            matches!(tls.read(&mut data), Ok(0) | Err(_)),
            "NEM application data was sent before pin validation"
        );
    });
    let error = Gateway::connect(&profile, "fixture&password", None)
        .err()
        .unwrap();
    assert!(format!("{error:#}").contains("SHA-256 mismatch"));
    server.join().unwrap();
}

fn legacy_wire(command: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0xfe, 0xfc, 0xef, 0xbe, 0xc1, 0x92, 0xa4, 0xd6];
    out.extend_from_slice(&42u32.to_be_bytes());
    out.extend_from_slice(&command.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}
fn read_legacy_wire(stream: &mut impl Read, command: u16) -> Vec<u8> {
    let mut header = [0u8; 16];
    stream.read_exact(&mut header).unwrap();
    assert_eq!(
        &header[..8],
        &[0xfe, 0xfc, 0xef, 0xbe, 0xc1, 0x92, 0xa4, 0xd6]
    );
    assert_eq!(&header[8..12], &42u32.to_be_bytes());
    assert_eq!(u16::from_be_bytes([header[12], header[13]]), command);
    let mut body = vec![0u8; u16::from_be_bytes([header[14], header[15]]) as usize];
    stream.read_exact(&mut body).unwrap();
    body
}
fn read_web_auth(stream: &mut impl Read) {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        assert!(header.len() < 16 * 1024);
        let mut byte = [0u8];
        stream.read_exact(&mut byte).unwrap();
        header.push(byte[0]);
    }
    let header = String::from_utf8(header).unwrap();
    assert!(header.starts_with("GET /netextension/netextensionlogin.html?SelectLanguage=0&UserName=loopback-user&Password=fixture%26password&MacAddress="));
    assert!(header.contains("&SVN_Seco_AaA=1& HTTP/1.1\r\n"));
    assert!(
        !header.contains("Zml4dHVyZS"),
        "Native authentication must not use browser Base64 credentials"
    );
}

#[test]
fn legacy_discovery_http_auth_and_nem_data_use_three_distinct_tls_connections() {
    let (acceptor, pin) = test_identity();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let profile = Profile {
        host: "127.0.0.1".into(),
        port: listener.local_addr().unwrap().port(),
        username: "loopback-user".into(),
        certificate_sha256: pin,
        transport: sslray_core::config::TransportMode::Tls,
        ..Profile::default()
    };
    let server = thread::spawn(move || {
        let mut discovery = acceptor.accept(bounded_socket(&listener)).unwrap();
        let mut first = [0u8; 340];
        discovery.read_exact(&mut first).unwrap();
        assert_eq!(
            &first[..8],
            &[0xfe, 0xfc, 0xef, 0xbe, 0xc1, 0x92, 0xa4, 0xd6]
        );
        let mut hello = legacy_wire(0x1d, &[0; 776]);
        hello[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        discovery.write_all(&hello).unwrap();
        let mut after_hello = [0u8];
        assert!(
            matches!(discovery.read(&mut after_hello), Ok(0) | Err(_)),
            "HTTP authentication reused binary discovery connection"
        );
        drop(discovery);

        let mut auth = acceptor.accept(bounded_socket(&listener)).unwrap();
        read_web_auth(&mut auth);
        let mut authenticated = vec![0u8; 1024];
        authenticated[..4].copy_from_slice(&[0xf0; 4]);
        authenticated[8..12].copy_from_slice(&7u32.to_be_bytes()); // VTID
        authenticated[12..16].copy_from_slice(&314u32.to_be_bytes());
        authenticated[44..48].copy_from_slice(&42u32.to_be_bytes());
        let cookie = b"fixture-legacy-session";
        authenticated[88..88 + cookie.len()].copy_from_slice(cookie);
        auth.write_all(&authenticated).unwrap();

        let mut data = acceptor.accept(bounded_socket(&listener)).unwrap();
        // Preserve native TLS-record compatibility: header and four-byte bind
        // payload must arrive from a single SSL_write, not separate records.
        let mut acl = [0u8; 20];
        assert_eq!(data.read(&mut acl).unwrap(), 20);
        assert_eq!(acl.as_slice(), legacy_wire(6, &0u32.to_be_bytes()));
        // Company firmware writes this ACK's 20-byte payload length as LE.
        // Coalesce a following keepalive to verify the next frame is preserved.
        let mut acl_reply = legacy_wire(6, &[0; 20]);
        acl_reply[14..16].copy_from_slice(&[20, 0]);
        acl_reply.extend_from_slice(&legacy_wire(7, &[]));
        data.write_all(&acl_reply).unwrap();
        assert!(read_legacy_wire(&mut data, 3).is_empty());
        let mut config = vec![0u8; 12476];
        config[..4].copy_from_slice(&[10, 77, 0, 2]);
        config[4..8].copy_from_slice(&[255, 255, 255, 0]);
        config[184..188].copy_from_slice(&1u32.to_be_bytes());
        config[188..192].copy_from_slice(&[10, 77, 0, 0]);
        config[192..196].copy_from_slice(&[255, 255, 255, 0]);
        data.write_all(&legacy_wire(3, &config)).unwrap();
        let payload = read_legacy_wire(&mut data, 2);
        assert_eq!(payload, ipv4_packet());
        data.write_all(&legacy_wire(7, &[])).unwrap();
        let response = legacy_wire(2, &payload);
        data.write_all(&response[..19]).unwrap();
        thread::sleep(Duration::from_millis(180));
        data.write_all(&response[19..]).unwrap();
        let mut logout = acceptor.accept(bounded_socket(&listener)).unwrap();
        let mut logout_header = Vec::new();
        while !logout_header.ends_with(b"\r\n\r\n") {
            assert!(logout_header.len() < 16 * 1024);
            let mut byte = [0u8];
            logout.read_exact(&mut byte).unwrap();
            logout_header.push(byte[0]);
        }
        let logout_header = String::from_utf8(logout_header).unwrap();
        assert!(logout_header.starts_with(
            "GET /logout.html?VTID=7&UserID=42&SessionID=314&SelectLanguage=2& HTTP/1.1\r\n"
        ));
        assert!(
            logout_header
                .lines()
                .any(|line| line == "Cookie: SVN_SessionID=fixture-legacy-session")
        );
        assert!(!logout_header.contains("Password="));
        logout
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });
    let gateway = Gateway::connect(&profile, "fixture&password", None).unwrap();
    assert_eq!(gateway.transport, "TLS/TCP (Huawei legacy)");
    gateway.set_read_budget(Duration::from_millis(100)).unwrap();
    round_trip(gateway);
    server.join().unwrap();
}
