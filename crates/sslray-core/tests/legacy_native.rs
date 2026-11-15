//! Local verified-TLS fixtures for the native Huawei authentication exchange.
//! No real gateway, credentials, privileged interface or route is used.
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::PKey,
    ssl::{SslAcceptor, SslMethod, SslStream},
    x509::{X509, X509NameBuilder},
};
use sslray_core::{config::Profile, crypto, legacy_native};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const PASSWORD: &str = "fixture-password&+?";
const OTP: &str = "12+&?";
const COOKIE: &str = "fixture-native-secret-cookie";

fn fixture(
    handler: impl FnOnce(SslAcceptor, TcpListener) + Send + 'static,
) -> (Profile, JoinHandle<()>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "SSLRay native auth fixture")
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
    acceptor.set_certificate(&cert).unwrap();
    acceptor.set_private_key(&key).unwrap();
    acceptor.check_private_key().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let profile = Profile {
        host: "127.0.0.1".into(),
        port: listener.local_addr().unwrap().port(),
        username: "fixture+user".into(),
        certificate_sha256: pin,
        ..Profile::default()
    };
    let server = thread::spawn(move || handler(acceptor.build(), listener));
    (profile, server)
}

fn accept(acceptor: &SslAcceptor, listener: &TcpListener) -> SslStream<TcpStream> {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "Expected native TLS connection");
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("Local native TLS accept failed: {error}"),
        }
    };
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    acceptor.accept(socket).unwrap()
}

fn request(stream: &mut impl Read) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 16 * 1024, "Unbounded native request");
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
    }
    String::from_utf8(bytes).unwrap()
}

fn primary_request(stream: &mut impl Read) {
    let headers = request(stream);
    assert!(headers.starts_with("GET /netextension/netextensionlogin.html?SelectLanguage=0&UserName=fixture%2Buser&Password=fixture-password%26%2B%3F&MacAddress="));
    assert!(headers.contains("&SVN_Seco_AaA=1& HTTP/1.1\r\n"));
    assert!(!headers.contains("Cookie:"));
}

fn native_record(status: i32, sms: bool, cookie: &str, wire_length: usize) -> Vec<u8> {
    assert!((88..=1024).contains(&wire_length));
    let mut record = vec![0; wire_length];
    record[..4].fill(0xf0);
    let body = &mut record[4..];
    body[..4].copy_from_slice(&status.to_be_bytes());
    body[4..8].copy_from_slice(&7u32.to_be_bytes());
    body[8..12].copy_from_slice(&314u32.to_be_bytes());
    body[0x28..0x2c].copy_from_slice(&42u32.to_be_bytes());
    body[0x32..0x34].copy_from_slice(&u16::from(sms).to_be_bytes());
    assert!(cookie.len() < body.len() - 0x54);
    body[0x54..0x54 + cookie.len()].copy_from_slice(cookie.as_bytes());
    record
}

fn no_challenge(_: &str) -> anyhow::Result<Zeroizing<String>> {
    panic!("Unexpected native SMS callback");
}

fn assert_redacted(error: &anyhow::Error) {
    let text = format!("{error:#}");
    for secret in [
        PASSWORD,
        "fixture-password%26%2B%3F",
        OTP,
        "12%2B%26%3F",
        COOKIE,
    ] {
        assert!(
            !text.contains(secret),
            "Authentication error exposed a secret"
        );
    }
}

#[test]
fn negative_primary_status_can_request_sms_on_a_fresh_verified_tls_connection() {
    let (profile, server) = fixture(|acceptor, listener| {
        let mut primary = accept(&acceptor, &listener);
        primary_request(&mut primary);
        primary
            .write_all(&native_record(-100, true, COOKIE, 1024))
            .unwrap();
        let mut byte = [0];
        assert!(matches!(primary.read(&mut byte), Ok(0) | Err(_)));
        drop(primary);

        let mut sms = accept(&acceptor, &listener);
        let headers = request(&mut sms);
        assert!(headers.starts_with("GET /checkrdsverificationcode.html?VTID=7&UserID=42&SessionID=314&SMSCode=12%2B%26%3F&SelectLanguage=2& HTTP/1.1\r\n"));
        assert!(
            headers
                .lines()
                .any(|s| s == format!("Cookie: SVN_SessionID={COOKIE}"))
        );
        assert!(!headers.contains("Password=") && !headers.contains("UserName="));
        sms.write_all(&native_record(0, false, "fixture-completed", 1024))
            .unwrap();
        // The caller must receive the authenticated secondary connection.
        sms.write_all(b"ok").unwrap();
    });
    let mut tls = crypto::connect(&profile).unwrap();
    let mut callbacks = 0;
    let auth = legacy_native::authenticate_on(&profile, &mut tls, PASSWORD, |kind| {
        assert_eq!(kind, "sms");
        callbacks += 1;
        Ok(Zeroizing::new(OTP.into()))
    })
    .unwrap();
    assert_eq!(callbacks, 1);
    assert_eq!(auth.user_id, 42);
    assert_eq!(auth.random_id, 314);
    assert_eq!(auth.vtid, 7);
    assert!(auth.native_auth);
    assert_eq!(auth.cookie.as_str(), "fixture-completed");
    let mut marker = [0; 2];
    tls.read_exact(&mut marker).unwrap();
    assert_eq!(&marker, b"ok");
    server.join().unwrap();
}

#[test]
fn rejected_sms_has_one_callback_no_replay_and_bounded_session_logout() {
    let (profile, server) = fixture(|acceptor, listener| {
        let mut primary = accept(&acceptor, &listener);
        primary_request(&mut primary);
        primary
            .write_all(&native_record(-100, true, COOKIE, 1024))
            .unwrap();
        let mut sms = accept(&acceptor, &listener);
        let headers = request(&mut sms);
        assert!(headers.starts_with("GET /checkrdsverificationcode.html?"));
        assert!(!headers.contains("Password="));
        sms.write_all(&native_record(-100, true, COOKIE, 1024))
            .unwrap();
        drop(sms);
        drop(primary);

        // Failure cleanup is a third connection; it must never replay the OTP.
        let mut logout = accept(&acceptor, &listener);
        let headers = request(&mut logout);
        assert!(headers.starts_with(
            "GET /logout.html?VTID=7&UserID=42&SessionID=314&SelectLanguage=2& HTTP/1.1\r\n"
        ));
        assert!(
            headers
                .lines()
                .any(|s| s == format!("Cookie: SVN_SessionID={COOKIE}"))
        );
        assert!(!headers.contains("SMSCode=") && !headers.contains("Password="));
        logout
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .unwrap();
    });
    let mut tls = crypto::connect(&profile).unwrap();
    let mut callbacks = 0;
    let error = legacy_native::authenticate_on(&profile, &mut tls, PASSWORD, |kind| {
        assert_eq!(kind, "sms");
        callbacks += 1;
        Ok(Zeroizing::new(OTP.into()))
    })
    .err()
    .expect("Unchanged native SMS flag must reject the OTP");
    assert_eq!(callbacks, 1);
    assert!(error.to_string().contains("no automatic retry"));
    assert_redacted(&error);
    server.join().unwrap();
}

#[test]
fn accepts_short_145_byte_native_records_with_nul_terminated_or_empty_cookie() {
    for cookie in ["fixture-short-cookie", ""] {
        let (profile, server) = fixture(move |acceptor, listener| {
            let mut tls = accept(&acceptor, &listener);
            primary_request(&mut tls);
            tls.write_all(&native_record(0, false, cookie, 145))
                .unwrap();
            tls.shutdown().unwrap();
        });
        let mut tls = crypto::connect(&profile).unwrap();
        let auth =
            legacy_native::authenticate_on(&profile, &mut tls, PASSWORD, no_challenge).unwrap();
        assert_eq!(auth.user_id, 42);
        assert_eq!(auth.cookie.as_str(), cookie);
        server.join().unwrap();
    }
}

#[test]
fn malformed_short_cookie_and_denied_authentication_do_not_echo_secrets() {
    let mut unterminated = native_record(0, false, COOKIE, 145);
    unterminated[4 + 0x54..].fill(b'x');
    let denied = native_record(-100, false, COOKIE, 1024);
    let truncated = native_record(0, false, COOKIE, 145)[..87].to_vec();
    for response in [unterminated, denied, truncated] {
        let (profile, server) = fixture(move |acceptor, listener| {
            let mut tls = accept(&acceptor, &listener);
            primary_request(&mut tls);
            tls.write_all(&response).unwrap();
            tls.shutdown().unwrap();
        });
        let mut tls = crypto::connect(&profile).unwrap();
        let error = legacy_native::authenticate_on(&profile, &mut tls, PASSWORD, no_challenge)
            .err()
            .expect("Malformed or denied native authentication must fail");
        assert_redacted(&error);
        server.join().unwrap();
    }
}

#[test]
fn short_negative_status_is_classified_after_a_bounded_read_without_replaying_login() {
    let (release_tx, release_rx) = mpsc::channel();
    let (profile, server) = fixture(move |acceptor, listener| {
        let mut tls = accept(&acceptor, &listener);
        primary_request(&mut tls);
        let mut response = vec![0xf0; 4];
        response.extend_from_slice(&(-5i32).to_be_bytes());
        response.extend_from_slice(&[0, 0]);
        tls.write_all(&response).unwrap();
        // Hold TLS open until the bounded read has classified the short refusal.
        // Trailing bytes must not turn that status into an I/O failure.
        release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        tls.get_ref()
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut byte = [0];
        assert!(
            matches!(
                tls.read(&mut byte),
                Err(error) if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                )
            ),
            "Authentication refusal sent additional application data"
        );
        assert!(
            matches!(
                listener.accept(),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            ),
            "Authentication refusal opened a second connection"
        );
    });
    let mut tls = crypto::connect(&profile).unwrap();
    let start = Instant::now();
    let result = legacy_native::authenticate_on(&profile, &mut tls, PASSWORD, no_challenge);
    let elapsed = start.elapsed();
    release_tx.send(()).unwrap();
    server.join().unwrap();
    let error = result
        .err()
        .expect("Negative native status must be refused");
    assert!(
        error
            .to_string()
            .contains("rejected authentication (status -5)")
    );
    assert!(error.to_string().contains("no automatic retry"));
    assert!(
        elapsed < Duration::from_secs(2),
        "Short refusal exceeded the bounded authentication read"
    );
    assert_redacted(&error);
}
