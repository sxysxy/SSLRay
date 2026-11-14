//! Credential-free TLS preflight. All certificates are generated locally and
//! every socket is loopback; no interfaces, routes or administrator are used.
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{SslAcceptor, SslMethod, SslVersion},
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
    },
};
use sslray_core::{
    config::{CryptoMode, Profile},
    crypto::{self, CertificateReport},
};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::Command,
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Identity {
    acceptor: SslAcceptor,
    certificate: X509,
    fingerprint: String,
}
fn key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}
fn certificate(expired: bool, matches_name: bool, signing_key: Option<&PKey<Private>>) -> Identity {
    let private = key();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "SSLRay certificate loopback")
        .unwrap();
    let name = name.build();
    let mut certificate = X509::builder().unwrap();
    certificate.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    certificate
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    certificate.set_subject_name(&name).unwrap();
    certificate.set_issuer_name(&name).unwrap();
    certificate.set_pubkey(&private).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    certificate
        .set_not_before(&Asn1Time::from_unix(now - 86400).unwrap())
        .unwrap();
    certificate
        .set_not_after(
            &Asn1Time::from_unix(if expired { now - 3600 } else { now + 86400 }).unwrap(),
        )
        .unwrap();
    let mut names = SubjectAlternativeName::new();
    if matches_name {
        names.ip("127.0.0.1");
    } else {
        names.dns("different.invalid");
    }
    let extension = names
        .build(&certificate.x509v3_context(None, None))
        .unwrap();
    certificate.append_extension(extension).unwrap();
    certificate
        .sign(signing_key.unwrap_or(&private), MessageDigest::sha256())
        .unwrap();
    identity(certificate.build(), &private)
}
fn identity(certificate: X509, private: &PKey<Private>) -> Identity {
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    acceptor.set_private_key(private).unwrap();
    acceptor.set_certificate(&certificate).unwrap();
    acceptor.check_private_key().unwrap();
    let fingerprint = hex::encode(certificate.digest(MessageDigest::sha256()).unwrap());
    Identity {
        acceptor: acceptor.build(),
        certificate,
        fingerprint,
    }
}
fn socket(listener: &TcpListener) -> TcpStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    let socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "Certificate test TLS accept timed out"
                );
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("Certificate test TLS accept failed: {error}"),
        }
    };
    socket.set_nonblocking(false).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    socket
}
fn server(acceptor: &SslAcceptor, expected: Option<&'static [u8]>) -> (Profile, JoinHandle<()>) {
    let acceptor = acceptor.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let profile = Profile {
        host: "127.0.0.1".into(),
        port: listener.local_addr().unwrap().port(),
        ..Profile::default()
    };
    let worker = thread::spawn(move || match acceptor.accept(socket(&listener)) {
        Ok(mut stream) => {
            if let Some(expected) = expected {
                let mut bytes = vec![0; expected.len()];
                stream.read_exact(&mut bytes).unwrap();
                assert_eq!(bytes, expected);
                stream.write_all(b"accepted").unwrap();
            } else {
                let mut bytes = [0; 1];
                assert!(
                    matches!(stream.read(&mut bytes), Ok(0) | Err(_)),
                    "Preflight/rejected pin sent application data"
                );
            }
        }
        Err(error) => assert!(
            expected.is_none(),
            "Expected approved TLS connection: {error}"
        ),
    });
    (profile, worker)
}
fn assert_no_unpinned_connection(identity: &Identity) {
    let (profile, worker) = server(&identity.acceptor, None);
    assert!(
        crypto::connect(&profile).is_err(),
        "Preflight must not change normal certificate validation"
    );
    worker.join().unwrap();
}

#[test]
fn self_signed_preflight_reports_identity_without_sending_application_data() {
    let identity = certificate(false, true, None);
    let (profile, worker) = server(&identity.acceptor, None);
    let report = crypto::check_certificate(&profile).unwrap();
    assert_eq!(report.certificate_sha256, identity.fingerprint);
    assert_eq!(
        report.not_before,
        identity.certificate.not_before().to_string()
    );
    assert_eq!(
        report.not_after,
        identity.certificate.not_after().to_string()
    );
    assert!(!report.subject.is_empty() && !report.issuer.is_empty());
    assert!(
        report
            .verification_errors
            .iter()
            .any(|e| e.contains("self-signed"))
    );
    let round_trip: CertificateReport =
        serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
    assert_eq!(round_trip, report);
    worker.join().unwrap();
    assert_no_unpinned_connection(&identity);
}

#[test]
fn expired_preflight_records_dates_but_normal_connection_still_refuses() {
    let identity = certificate(true, true, None);
    let (profile, worker) = server(&identity.acceptor, None);
    let report = crypto::check_certificate(&profile).unwrap();
    assert!(
        report
            .verification_errors
            .iter()
            .any(|e| e.contains("expired"))
    );
    worker.join().unwrap();
    assert_no_unpinned_connection(&identity);
}

#[test]
fn hostname_mismatch_is_reported_with_the_untrusted_chain_warning() {
    let identity = certificate(false, false, None);
    let (profile, worker) = server(&identity.acceptor, None);
    let report = crypto::check_certificate(&profile).unwrap();
    assert!(
        report
            .verification_errors
            .iter()
            .any(|e| e.contains("mismatch")),
        "{:?}",
        report.verification_errors
    );
    worker.join().unwrap();
}

#[test]
fn approved_pin_connects_but_a_changed_certificate_or_wrong_pin_is_refused() {
    let original = certificate(true, true, None);
    let (mut profile, worker) = server(&original.acceptor, Some(b"approved"));
    profile.certificate_sha256 = original.fingerprint.clone();
    let mut stream = crypto::connect(&profile).unwrap();
    stream.write_all(b"approved").unwrap();
    let mut reply = [0; 8];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"accepted");
    drop(stream);
    worker.join().unwrap();

    let (mut profile, worker) = server(&original.acceptor, None);
    profile.certificate_sha256 = original.fingerprint.clone();
    assert!(
        crypto::check_certificate(&profile)
            .unwrap()
            .verification_errors
            .is_empty()
    );
    worker.join().unwrap();

    let rotated = certificate(false, true, None);
    for (identity, pin) in [
        (&rotated, original.fingerprint.clone()),
        (&original, "00".repeat(32)),
    ] {
        let (mut profile, worker) = server(&identity.acceptor, None);
        profile.certificate_sha256 = pin.clone();
        let error = crypto::check_certificate(&profile).unwrap_err();
        assert!(format!("{error:#}").contains("SHA-256 mismatch"));
        worker.join().unwrap();
        let (mut profile, worker) = server(&identity.acceptor, None);
        profile.certificate_sha256 = pin;
        assert!(crypto::connect(&profile).is_err());
        worker.join().unwrap();
    }
}

#[test]
fn cryptographically_invalid_self_signed_certificate_is_not_an_approvable_warning() {
    let wrong_signing_key = key();
    let identity = certificate(false, true, Some(&wrong_signing_key));
    let (profile, worker) = server(&identity.acceptor, None);
    assert!(crypto::check_certificate(&profile).is_err());
    worker.join().unwrap();
}

#[test]
fn inspect_retains_existing_fields_and_adds_start_date_and_verification_errors() {
    let identity = certificate(false, true, None);
    let (profile, worker) = server(&identity.acceptor, None);
    let report = crypto::inspect(&profile).unwrap();
    for field in [
        "host",
        "port",
        "certificate_sha256",
        "subject",
        "issuer",
        "not_after",
        "tls",
        "cipher",
        "trusted",
        "notice",
        "not_before",
        "verification_errors",
    ] {
        assert!(
            report.get(field).is_some(),
            "Missing discovery field {field}"
        );
    }
    assert_eq!(report["trusted"], false);
    assert!(!report["verification_errors"].as_array().unwrap().is_empty());
    worker.join().unwrap();
}

#[test]
fn gm_preflight_cannot_fall_back_to_a_standard_tls12_server() {
    if !crypto::capabilities().gm_tls13 {
        return;
    }
    let mut identity = certificate(false, true, None);
    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    // Reuse the existing server through a TLS1.2-only SSL_CTX configuration.
    // A GM-only client must fail at protocol negotiation before any report.
    let private = key();
    let mut cert = X509::builder().unwrap();
    cert.set_version(2).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "TLS1.2 only").unwrap();
    let name = name.build();
    cert.set_subject_name(&name).unwrap();
    cert.set_issuer_name(&name).unwrap();
    cert.set_pubkey(&private).unwrap();
    cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    cert.sign(&private, MessageDigest::sha256()).unwrap();
    acceptor.set_certificate(&cert.build()).unwrap();
    acceptor.set_private_key(&private).unwrap();
    acceptor
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .unwrap();
    identity.acceptor = acceptor.build();
    let (mut profile, worker) = server(&identity.acceptor, None);
    profile.crypto = CryptoMode::GmTls13;
    assert!(crypto::check_certificate(&profile).is_err());
    worker.join().unwrap();
}

fn trusted_ca_identity() -> (Identity, X509) {
    let ca_key = key();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "SSLRay local test CA")
        .unwrap();
    let name = name.build();
    let mut ca = X509::builder().unwrap();
    ca.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
    ca.set_serial_number(&serial).unwrap();
    ca.set_subject_name(&name).unwrap();
    ca.set_issuer_name(&name).unwrap();
    ca.set_pubkey(&ca_key).unwrap();
    ca.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    ca.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    ca.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    ca.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()
            .unwrap(),
    )
    .unwrap();
    ca.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let ca = ca.build();
    let leaf_key = key();
    let mut leaf = X509::builder().unwrap();
    leaf.set_version(2).unwrap();
    leaf.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    let mut leaf_name = X509NameBuilder::new().unwrap();
    leaf_name
        .append_entry_by_text("CN", "SSLRay trusted loopback leaf")
        .unwrap();
    leaf.set_subject_name(&leaf_name.build()).unwrap();
    leaf.set_issuer_name(ca.subject_name()).unwrap();
    leaf.set_pubkey(&leaf_key).unwrap();
    leaf.set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    leaf.set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    leaf.append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    leaf.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .build()
            .unwrap(),
    )
    .unwrap();
    leaf.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .ip("127.0.0.1")
        .build(&leaf.x509v3_context(Some(&ca), None))
        .unwrap();
    leaf.append_extension(san).unwrap();
    leaf.sign(&ca_key, MessageDigest::sha256()).unwrap();
    (identity(leaf.build(), &leaf_key), ca)
}
#[test]
fn a_trusted_ca_and_matching_name_produce_no_warnings() {
    // Change OpenSSL's trust environment only in a child test process; other
    // parallel tests must not accidentally inherit this temporary CA.
    if let Some(port) = std::env::var_os("SSLRAY_CERTIFICATE_TEST_PORT") {
        let profile = Profile {
            host: "127.0.0.1".into(),
            port: port.to_str().unwrap().parse().unwrap(),
            ..Profile::default()
        };
        let report = crypto::check_certificate(&profile).unwrap();
        assert!(
            report.verification_errors.is_empty(),
            "{:?}",
            report.verification_errors
        );
        return;
    }
    let (identity, ca) = trusted_ca_identity();
    let dir = std::env::temp_dir().join(format!(
        "sslray-certificate-ca-{}-{}",
        std::process::id(),
        &identity.fingerprint[..16]
    ));
    std::fs::create_dir(&dir).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let ca_file = dir.join("ca.pem");
    std::fs::write(&ca_file, ca.to_pem().unwrap()).unwrap();
    let (profile, worker) = server(&identity.acceptor, None);
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "a_trusted_ca_and_matching_name_produce_no_warnings",
            "--nocapture",
        ])
        .env("SSLRAY_CERTIFICATE_TEST_PORT", profile.port.to_string())
        .env("SSL_CERT_FILE", ca_file)
        .env("SSL_CERT_DIR", &dir)
        .output()
        .unwrap();
    worker.join().unwrap();
    assert!(
        output.status.success(),
        "Trusted-CA child failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
