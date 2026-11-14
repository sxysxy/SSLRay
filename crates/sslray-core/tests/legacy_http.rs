//! Isolated HTTPS web-auth fixtures for older Huawei gateways. All identities and
//! secrets below are test fixtures; sockets bind only to loopback and no TUN is used.
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
use sslray_core::{config::Profile, crypto, legacy_http};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    thread::{self, JoinHandle},
    time::Duration,
};
use zeroize::Zeroizing;

fn server(
    handler: impl FnOnce(&mut SslStream<TcpStream>) + Send + 'static,
) -> (Profile, JoinHandle<()>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "SSLRay legacy HTTPS fixture")
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
    let mut tls = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    tls.set_certificate(&cert).unwrap();
    tls.set_private_key(&key).unwrap();
    let tls = tls.build();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let profile = Profile {
        host: "127.0.0.1".into(),
        port: listener.local_addr().unwrap().port(),
        username: "测试+user".into(),
        certificate_sha256: pin,
        ..Profile::default()
    };
    let worker = thread::spawn(move || {
        let socket = listener.accept().unwrap().0;
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut stream = tls.accept(socket).unwrap();
        handler(&mut stream);
    });
    (profile, worker)
}
fn request(stream: &mut impl Read) -> (String, String) {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 16 * 1024);
        let mut byte = [0u8];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
    }
    let header = String::from_utf8(bytes).unwrap();
    let length = header
        .lines()
        .filter_map(|s| s.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.trim().parse::<usize>().unwrap())
        .unwrap_or(0);
    assert!(length < 16 * 1024);
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).unwrap();
    (header, String::from_utf8(body).unwrap())
}
fn no_challenge(_: &str) -> anyhow::Result<Zeroizing<String>> {
    panic!("Unexpected MFA challenge");
}

#[test]
fn fresh_https_post_uses_served_web_base64_then_form_encoding() {
    let (profile, worker) = server(|stream| {
        let (headers, body) = request(stream);
        assert!(headers.starts_with("POST /login.html HTTP/1.1\r\n"));
        assert!(headers.contains("Content-Type: application/x-www-form-urlencoded\r\n"));
        assert!(headers.contains("Accept-Encoding: identity\r\n"));
        // Independent expected output from the gateway's UTF8+base64 web form.
        assert_eq!(
            body,
            "UserName=5rWL6K%2BVK3VzZXI%3D&Password=5a%2BG56CBJislPy8%2F&MacAddress=FFFF-FFFF-FFFF&SVN_Seco_AaA=1&SelectLanguage=0&VerificationCode=&VerificationCodeId=&aaa=1"
        );
        stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: /main.html?UserID=42&RandomID=314&\r\nSet-Cookie: UserID=42&SVN_SessionID=fixture-session; secure\r\nContent-Length: 0\r\n\r\n").unwrap();
    });
    let mut tls = crypto::connect(&profile).unwrap();
    let auth =
        legacy_http::authenticate_on(&profile, &mut tls, "密码&+%?/?", no_challenge).unwrap();
    assert_eq!(auth.user_id, 42);
    assert_eq!(auth.random_id, 314);
    assert_eq!(auth.cookie.as_str(), "fixture-session");
    worker.join().unwrap();
}

#[test]
fn sms_followup_preserves_combined_huawei_cookie_without_replaying_password() {
    let (profile, worker) = server(|stream| {
        let (_, body) = request(stream);
        assert!(body.contains("Password="));
        stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: /rdsverificationcode.html?VTID=77&\r\nSet-Cookie: UserID=42&SVN_SessionID=fixture-challenge; secure\r\nContent-Length: 0\r\n\r\n").unwrap();
        let (headers, body) = request(stream);
        assert!(headers.starts_with("GET /checkrdsverificationcode.html?VTID=77&SMSCode=12%2B%26%3F&SelectLanguage=2& HTTP/1.1\r\n"));
        assert!(
            headers
                .lines()
                .any(|line| line == "Cookie: UserID=42&SVN_SessionID=fixture-challenge;")
        );
        assert!(!headers.contains("Password=") && !headers.contains("UserName="));
        assert!(body.is_empty());
        stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: /main.html?UserID=42&\r\nSet-Cookie: UserID=42&SVN_SessionID=fixture-completed; secure\r\nContent-Length: 0\r\n\r\n").unwrap();
    });
    let mut tls = crypto::connect(&profile).unwrap();
    let mut prompted = 0;
    let auth = legacy_http::authenticate_on(&profile, &mut tls, "密码&+%?/?", |method| {
        assert_eq!(method, "sms");
        prompted += 1;
        Ok(Zeroizing::new("12+&?".into()))
    })
    .unwrap();
    assert_eq!(prompted, 1);
    assert_eq!(auth.random_id, 0);
    assert_eq!(auth.cookie.as_str(), "fixture-completed");
    worker.join().unwrap();
}

#[test]
fn rejects_oversized_ambiguous_and_compressed_http_without_echoing_secrets() {
    let mut oversized_header = b"HTTP/1.1 302 Found\r\nX-Test: ".to_vec();
    oversized_header.extend(vec![b'a'; 65536]);
    oversized_header.extend_from_slice(b"\r\n\r\n");
    let cases = [
        b"HTTP/1.1 302 Found\r\nContent-Length: 1048577\r\n\r\n".to_vec(),
        b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"HTTP/1.1 302 Found\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec(),
        b"HTTP/1.1 302 Found\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"HTTP/1.1 401 Unauthorized\r\nLocation: /rdsverificationcode.html?VTID=77&\r\nSet-Cookie: UserID=42&SVN_SessionID=fixture-challenge; secure\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"HTTP/1.1 302 Found\r\nLocation: /relogin.html?ReloginCause=3&Password=fixture-secret&\r\nSet-Cookie: SVN_SessionID=fixture-cookie-secret; secure\r\nContent-Length: 0\r\n\r\n".to_vec(),
        oversized_header,
    ];
    for response in cases {
        let (profile, worker) = server(move |stream| {
            request(stream);
            let _ = stream.write_all(&response);
        });
        let mut tls = crypto::connect(&profile).unwrap();
        let result =
            legacy_http::authenticate_on(&profile, &mut tls, "fixture-secret", no_challenge);
        assert!(result.is_err());
        let text = format!("{:#}", result.err().unwrap());
        assert!(!text.contains("fixture-secret"));
        assert!(!text.contains("fixture-cookie-secret"));
        drop(tls);
        worker.join().unwrap();
    }
}

#[test]
fn cookie_must_come_from_set_cookie_and_must_not_be_ambiguous() {
    for response in [
        b"HTTP/1.1 302 Found\r\nLocation: /main.html?UserID=42&SVN_SessionID=misplaced-token&\r\nContent-Length: 0\r\n\r\n".as_slice(),
        b"HTTP/1.1 302 Found\r\nLocation: /main.html?UserID=42&\r\nSet-Cookie: SVN_SessionID=first-token; secure\r\nSet-Cookie: SVN_SessionID=second-token; secure\r\nContent-Length: 0\r\n\r\n".as_slice(),
    ] {
        let response = response.to_vec();
        let (profile, worker) = server(move |stream| {
            request(stream);
            stream.write_all(&response).unwrap();
        });
        let mut tls = crypto::connect(&profile).unwrap();
        let result = legacy_http::authenticate_on(&profile, &mut tls, "fixture-secret", no_challenge);
        assert!(result.is_err(), "An unscoped or ambiguous cookie was accepted");
        worker.join().unwrap();
    }
}
