//! Real RFC 8998 negotiation through the same connector used by VPN channels.
//! The test generates an ephemeral SM2 certificate and uses loopback only.
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::Id,
    pkey_ctx::PkeyCtx,
    ssl::{SslAcceptor, SslMethod, SslVersion},
    x509::{X509, X509NameBuilder},
};
use sslray_core::{
    config::{CryptoMode, Profile},
    crypto,
};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};

fn negotiate(cipher: &str) {
    let mut generator = PkeyCtx::new_id(Id::SM2).unwrap();
    generator.keygen_init().unwrap();
    let key = generator.keygen().unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "SSLRay SM2 loopback")
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
    certificate.set_pubkey(&key).unwrap();
    certificate
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    certificate
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    certificate.sign(&key, MessageDigest::sm3()).unwrap();
    let certificate = certificate.build();
    let pin = hex::encode(certificate.digest(MessageDigest::sha256()).unwrap());

    let mut server = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    server.set_private_key(&key).unwrap();
    server.set_certificate(&certificate).unwrap();
    server.check_private_key().unwrap();
    server
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .unwrap();
    server.set_ciphersuites(cipher).unwrap();
    server.set_groups_list("SM2").unwrap();
    server.set_sigalgs_list("sm2sig_sm3").unwrap();
    let server = server.build();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let profile = Profile {
        host: "127.0.0.1".into(),
        port: listener.local_addr().unwrap().port(),
        certificate_sha256: pin,
        crypto: CryptoMode::GmTls13,
        ..Profile::default()
    };
    let expected_cipher = cipher.to_owned();
    let worker = thread::spawn(move || {
        let socket = listener.accept().unwrap().0;
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut stream = server.accept(socket).unwrap();
        assert_eq!(stream.ssl().version_str(), "TLSv1.3");
        assert_eq!(
            stream.ssl().current_cipher().unwrap().name(),
            expected_cipher
        );
        let mut input = [0u8; 17];
        stream.read_exact(&mut input).unwrap();
        assert_eq!(&input, b"SSLRay GM payload");
        stream.write_all(b"GM response").unwrap();
        stream.flush().unwrap();
    });
    let mut stream = crypto::connect(&profile).unwrap();
    assert_eq!(stream.ssl().version_str(), "TLSv1.3");
    assert_eq!(stream.ssl().current_cipher().unwrap().name(), cipher);
    // Provider-backed OpenSSL 4 SM2 keys can return legacy Id(-1).
    // Check the encoded SM2 curve/algorithm OID instead of EVP_PKEY_id.
    let peer_key = stream
        .ssl()
        .peer_certificate()
        .unwrap()
        .public_key()
        .unwrap();
    let spki = peer_key.public_key_to_der().unwrap();
    let sm2_oid = [0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x82, 0x2d];
    assert!(spki.windows(sm2_oid.len()).any(|bytes| bytes == sm2_oid));
    stream.write_all(b"SSLRay GM payload").unwrap();
    let mut response = [0u8; 11];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response, b"GM response");
    worker.join().unwrap();
}

#[test]
fn actual_rfc8998_sm2_sm3_sm4_negotiation_and_encrypted_application_data() {
    let capabilities = crypto::capabilities();
    if !capabilities.gm_tls13 {
        eprintln!(
            "Skipping RFC 8998 loopback: {}: {}",
            capabilities.backend,
            capabilities.gm_error.unwrap_or_default()
        );
        return;
    }
    negotiate("TLS_SM4_GCM_SM3");
    negotiate("TLS_SM4_CCM_SM3");
}
