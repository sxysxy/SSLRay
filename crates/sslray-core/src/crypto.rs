//! TLS policy shared by both Huawei channels. No implicit insecure fallback.
use crate::config::{CryptoMode, Profile};
use anyhow::{Context, Result, bail, ensure};
use openssl::{
    hash::MessageDigest,
    ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion},
    x509::verify::X509VerifyFlags,
};
use serde::{Deserialize, Serialize};
use std::{
    net::{TcpStream, ToSocketAddrs},
    sync::{Arc, Mutex},
    time::Duration,
};

/// TCP transport used by client TLS streams. On Windows, normalize socket read
/// timeouts before OpenSSL's BIO sees them: Rust OpenSSL marks WouldBlock as
/// retryable, but TimedOut otherwise permanently fails OpenSSL's record layer.
#[cfg(windows)]
#[derive(Debug)]
pub struct TlsSocket(TcpStream);
#[cfg(not(windows))]
pub type TlsSocket = TcpStream;
pub type TlsStream = SslStream<TlsSocket>;

#[cfg(windows)]
impl From<TcpStream> for TlsSocket {
    fn from(socket: TcpStream) -> Self {
        Self(socket)
    }
}
#[cfg(windows)]
impl std::ops::Deref for TlsSocket {
    type Target = TcpStream;
    fn deref(&self) -> &TcpStream {
        &self.0
    }
}
#[cfg(windows)]
impl std::io::Read for TlsSocket {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        normalize_tls_read(std::io::Read::read(&mut self.0, bytes))
    }
}
#[cfg(windows)]
impl std::io::Write for TlsSocket {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut self.0, bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.0)
    }
}
#[cfg(any(windows, test))]
fn normalize_tls_read(result: std::io::Result<usize>) -> std::io::Result<usize> {
    result.map_err(|error| {
        if error.kind() == std::io::ErrorKind::TimedOut {
            std::io::Error::new(std::io::ErrorKind::WouldBlock, error)
        } else {
            error
        }
    })
}

/// Public certificate metadata, not permission to send credentials. Nonempty
/// verification_errors require an explicit user decision before connecting.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateReport {
    pub certificate_sha256: String,
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub verification_errors: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Capabilities {
    pub backend: String,
    pub gm_tls13: bool,
    pub gm_error: Option<String>,
}
pub fn capabilities() -> Capabilities {
    let result = connector(&Profile {
        crypto: CryptoMode::GmTls13,
        ..Profile::default()
    });
    Capabilities {
        backend: openssl::version::version().into(),
        gm_tls13: result.is_ok(),
        gm_error: result.err().map(|e| e.to_string()),
    }
}
pub fn connector(profile: &Profile) -> Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    #[cfg(windows)]
    if profile.certificate_sha256.is_empty() {
        crate::windows_roots::add_to_connector(&mut builder)
            .context("Loading Windows ROOT trust anchors")?;
    }
    #[cfg(target_os = "linux")]
    if use_linux_system_bundle(
        &profile.certificate_sha256,
        std::env::var_os("SSL_CERT_FILE").as_deref(),
        std::env::var_os("SSL_CERT_DIR").as_deref(),
    ) {
        load_linux_ca_bundle(
            &mut builder,
            &[
                "/etc/ssl/certs/ca-certificates.crt",
                "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/ca-bundle.pem",
                "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                "/etc/ssl/cert.pem",
            ],
        )?;
    }
    #[cfg(target_os = "macos")]
    if std::path::Path::new("/etc/ssl/cert.pem").is_file() {
        builder
            .set_ca_file("/etc/ssl/cert.pem")
            .context("Loading macOS CA bundle")?;
    }
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    if profile.crypto == CryptoMode::GmTls13 {
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_ciphersuites("TLS_SM4_GCM_SM3:TLS_SM4_CCM_SM3")
            .context("This TLS backend does not support RFC 8998 SM4/SM3 suites; build with a compatible Tongsuo backend")?;
        builder
            .set_groups_list("SM2")
            .context("TLS backend does not support the SM2 group")?;
        builder
            .set_sigalgs_list("sm2sig_sm3")
            .context("TLS backend does not support SM2/SM3 signatures")?;
    }
    if !profile.certificate_sha256.is_empty() {
        builder.set_verify(SslVerifyMode::NONE);
    }
    Ok(builder.build())
}

#[cfg(any(target_os = "linux", test))]
fn use_linux_system_bundle(
    pin: &str,
    ca_file: Option<&std::ffi::OsStr>,
    ca_dir: Option<&std::ffi::OsStr>,
) -> bool {
    // OpenSSL treats a present but empty variable as an explicit value too.
    // Preserve its configured CA sources without changing process environment.
    pin.is_empty() && ca_file.is_none() && ca_dir.is_none()
}

#[cfg(any(target_os = "linux", test))]
fn load_linux_ca_bundle<'a>(
    builder: &mut openssl::ssl::SslConnectorBuilder,
    candidates: &[&'a str],
) -> Result<Option<&'a str>> {
    for &bundle in candidates {
        let metadata = match std::fs::metadata(bundle) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("Reading Linux CA bundle {bundle}"));
            }
        };
        // Distribution-managed symlinks are followed. Minimal installations
        // may have no bundle or an empty bundle; preflight can still report an
        // untrusted certificate and explicit pins remain independent of CAs.
        if !metadata.is_file() || metadata.len() == 0 {
            continue;
        }
        builder
            .set_ca_file(bundle)
            .with_context(|| format!("Loading Linux CA bundle {bundle}"))?;
        return Ok(Some(bundle));
    }
    Ok(None)
}
pub fn connect(profile: &Profile) -> Result<TlsStream> {
    profile.validate()?;
    let connector = connector(profile)?;
    let mut config = connector.configure()?;
    if !profile.certificate_sha256.is_empty() {
        config.set_verify_hostname(false);
    }
    let socket = tcp_connect(profile)?;
    let stream = config
        .connect(&profile.host, socket)
        .map_err(|e| anyhow::anyhow!("TLS handshake failed: {e}"))?;
    verify_pin(&stream, &profile.certificate_sha256)?;
    verify_negotiated_crypto(&stream, profile)?;
    Ok(stream)
}
fn verify_negotiated_crypto(stream: &TlsStream, profile: &Profile) -> Result<()> {
    if profile.crypto == CryptoMode::GmTls13 {
        let cipher = stream
            .ssl()
            .current_cipher()
            .context("Missing negotiated cipher")?;
        ensure!(
            matches!(cipher.name(), "TLS_SM4_GCM_SM3" | "TLS_SM4_CCM_SM3"),
            "Gateway did not negotiate a GM cipher"
        );
    }
    Ok(())
}
fn tcp_connect(profile: &Profile) -> Result<TlsSocket> {
    let addresses: Vec<_> = (profile.host.as_str(), profile.port)
        .to_socket_addrs()?
        .collect();
    let mut last = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, Duration::from_secs(8)) {
            Ok(socket) => {
                socket.set_read_timeout(Some(Duration::from_secs(10)))?;
                socket.set_write_timeout(Some(Duration::from_secs(10)))?;
                socket.set_nodelay(true)?;
                #[cfg(windows)]
                let socket = TlsSocket::from(socket);
                return Ok(socket);
            }
            Err(e) => last = Some(e),
        }
    }
    bail!(
        "Gateway connection failed: {}",
        last.map(|e| e.to_string())
            .unwrap_or_else(|| "No DNS addresses".into())
    )
}
fn verify_pin(stream: &TlsStream, expected: &str) -> Result<()> {
    if expected.is_empty() {
        return Ok(());
    }
    let cert = stream
        .ssl()
        .peer_certificate()
        .context("Missing gateway certificate")?;
    let actual = cert.digest(MessageDigest::sha256())?;
    let expected = hex::decode(expected.replace(':', ""))?;
    ensure!(
        openssl::memcmp::eq(actual.as_ref(), &expected),
        "Gateway certificate SHA-256 mismatch; refusing authentication"
    );
    Ok(())
}
// Stable OpenSSL X509_V_ERR values. Only missing trust, certificate validity
// dates, and endpoint-name mismatches are eligible for explicit user approval.
// Invalid signatures, revocation, invalid CA constraints/purpose, weak keys,
// malformed dates, and unknown future errors remain fatal.
fn approvable_verification_error(code: i32) -> bool {
    matches!(code, 2 | 9 | 10 | 18 | 19 | 20 | 21 | 27 | 62 | 64)
}

fn certificate_stream(profile: &Profile) -> Result<(TlsStream, Vec<String>)> {
    profile.validate()?;
    certificate_stream_with_connector(profile, connector(profile)?)
}

fn certificate_stream_with_connector(
    profile: &Profile,
    connector: SslConnector,
) -> Result<(TlsStream, Vec<String>)> {
    let mut config = connector.configure()?;
    let errors = Arc::new(Mutex::new(Vec::<String>::new()));
    if profile.certificate_sha256.is_empty() {
        // Also check self-signed signatures; merely allowing an unknown issuer
        // must not allow a cryptographically invalid self-signed certificate.
        config
            .param_mut()
            .set_flags(X509VerifyFlags::CHECK_SS_SIGNATURE)?;
        let recorded = errors.clone();
        config.set_verify_callback(SslVerifyMode::PEER, move |verified, context| {
            if verified {
                return true;
            }
            let error = context.error();
            if !approvable_verification_error(error.as_raw()) {
                return false;
            }
            let Ok(mut errors) = recorded.lock() else {
                return false;
            };
            let message = format!(
                "{} (code {}, depth {})",
                error.error_string(),
                error.as_raw(),
                context.error_depth()
            );
            if !errors.contains(&message) {
                if errors.len() >= 32 {
                    return false;
                }
                errors.push(message);
            }
            true
        });
    } else {
        // Explicit pins retain the existing exact-leaf identity policy. A
        // mismatch is fatal even during this credential-free preflight.
        config.set_verify_hostname(false);
    }
    let stream = config
        .connect(&profile.host, tcp_connect(profile)?)
        .map_err(|e| anyhow::anyhow!("TLS certificate preflight failed: {e}"))?;
    verify_pin(&stream, &profile.certificate_sha256)?;
    verify_negotiated_crypto(&stream, profile)?;
    let errors = errors
        .lock()
        .map_err(|_| anyhow::anyhow!("Certificate verification state failed"))?
        .clone();
    Ok((stream, errors))
}

fn certificate_report(
    stream: &TlsStream,
    verification_errors: Vec<String>,
) -> Result<CertificateReport> {
    let cert = stream
        .ssl()
        .peer_certificate()
        .context("Missing certificate")?;
    Ok(CertificateReport {
        certificate_sha256: hex::encode(cert.digest(MessageDigest::sha256())?),
        subject: format!("{:?}", cert.subject_name()),
        issuer: format!("{:?}", cert.issuer_name()),
        not_before: cert.not_before().to_string(),
        not_after: cert.not_after().to_string(),
        verification_errors,
    })
}

/// Perform TLS only, without application data, credentials, interfaces or routes.
/// Approved warnings do not change connection policy: callers must obtain user
/// consent and pin this exact fingerprint in the current connection profile.
pub fn check_certificate(profile: &Profile) -> Result<CertificateReport> {
    let (stream, errors) = certificate_stream(profile)?;
    certificate_report(&stream, errors)
}

/// Certificate discovery sends no application data or credentials. This is not trust approval.
pub fn inspect(profile: &Profile) -> Result<serde_json::Value> {
    let (stream, errors) = certificate_stream(profile)?;
    let report = certificate_report(&stream, errors)?;
    Ok(serde_json::json!({
        "host": profile.host, "port": profile.port,
        "certificate_sha256": report.certificate_sha256,
        "subject": report.subject, "issuer": report.issuer,
        "not_before": report.not_before, "not_after": report.not_after,
        "verification_errors": report.verification_errors,
        "tls": stream.ssl().version_str(),
        "cipher": stream.ssl().current_cipher().map(|c| c.name()),
        "trusted": false,
        "notice": "Discovery only; verify this fingerprint with your VPN administrator before pinning."
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsStr, path::PathBuf};

    #[test]
    fn tls_read_timeout_is_retryable_but_eof_reset_and_other_errors_are_unchanged() {
        use std::io::{Error, ErrorKind};
        assert_eq!(normalize_tls_read(Ok(0)).unwrap(), 0);
        assert_eq!(normalize_tls_read(Ok(3)).unwrap(), 3);
        let retry =
            normalize_tls_read(Err(Error::new(ErrorKind::TimedOut, "read deadline"))).unwrap_err();
        assert_eq!(retry.kind(), ErrorKind::WouldBlock);
        assert_eq!(retry.get_ref().unwrap().to_string(), "read deadline");
        for kind in [
            ErrorKind::WouldBlock,
            ErrorKind::UnexpectedEof,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::InvalidData,
            ErrorKind::Interrupted,
        ] {
            let error = normalize_tls_read(Err(Error::new(kind, "unchanged"))).unwrap_err();
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), "unchanged");
        }
    }

    struct BundleFixture(PathBuf);
    impl BundleFixture {
        fn new() -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir()
                .join(format!("sslray-ca-bundle-{}-{unique}", std::process::id()));
            std::fs::create_dir(&directory).unwrap();
            Self(directory)
        }
        fn path(&self, filename: &str) -> String {
            self.0.join(filename).to_str().unwrap().to_owned()
        }
    }
    impl Drop for BundleFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn linux_system_bundle_respects_pins_and_explicit_ca_environment() {
        assert!(use_linux_system_bundle("", None, None));
        assert!(!use_linux_system_bundle("pinned", None, None));
        for value in [OsStr::new(""), OsStr::new("custom-ca-path")] {
            assert!(!use_linux_system_bundle("", Some(value), None));
            assert!(!use_linux_system_bundle("", None, Some(value)));
            assert!(!use_linux_system_bundle("", Some(value), Some(value)));
        }
    }

    #[test]
    fn linux_bundle_selection_skips_missing_directories_and_empty_but_not_invalid_files() {
        let fixture = BundleFixture::new();
        let missing = fixture.path("missing.pem");
        let directory = fixture.path("directory");
        std::fs::create_dir(&directory).unwrap();
        let empty = fixture.path("empty.pem");
        std::fs::write(&empty, []).unwrap();
        let invalid = fixture.path("invalid.pem");
        std::fs::write(&invalid, b"not a CA bundle").unwrap();
        let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
        assert_eq!(
            load_linux_ca_bundle(&mut builder, &[&missing, &directory, &empty]).unwrap(),
            None
        );
        let error = load_linux_ca_bundle(&mut builder, &[&invalid, &missing]).unwrap_err();
        assert!(error.to_string().contains("Loading Linux CA bundle"));
        assert!(error.to_string().contains(&invalid));
        #[cfg(unix)]
        {
            let not_directory = format!("{invalid}/cannot-read.pem");
            let error = load_linux_ca_bundle(&mut builder, &[&not_directory]).unwrap_err();
            assert!(error.to_string().contains("Reading Linux CA bundle"));
        }
    }

    #[test]
    fn linux_bundle_selection_loads_only_the_first_available_valid_bundle() {
        use openssl::{
            asn1::Asn1Time,
            ec::{EcGroup, EcKey},
            nid::Nid,
            pkey::PKey,
            x509::{X509, X509NameBuilder},
        };
        let fixture = BundleFixture::new();
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "SSLRay synthetic CA bundle")
            .unwrap();
        let name = name.build();
        let mut certificate = X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate
            .set_serial_number(
                &openssl::bn::BigNum::from_u32(1)
                    .unwrap()
                    .to_asn1_integer()
                    .unwrap(),
            )
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
        certificate.sign(&key, MessageDigest::sha256()).unwrap();
        let valid = fixture.path("valid.pem");
        std::fs::write(&valid, certificate.build().to_pem().unwrap()).unwrap();
        let later_invalid = fixture.path("later-invalid.pem");
        std::fs::write(&later_invalid, b"must not be loaded").unwrap();
        let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
        assert_eq!(
            load_linux_ca_bundle(&mut builder, &[&valid, &later_invalid]).unwrap(),
            Some(valid.as_str())
        );
    }

    #[test]
    fn standard_policy_builds() {
        connector(&Profile::default()).unwrap();
    }
    #[test]
    fn invalid_pin_fails_validation() {
        let p = Profile {
            certificate_sha256: "00".into(),
            ..Profile::default()
        };
        assert!(p.validate().is_err());
    }
    #[test]
    fn preflight_never_approves_signature_revocation_or_weak_algorithm_errors() {
        for code in [7, 8, 13, 14, 23, 26, 28, 66, 67, 68, 77, 78, 79, 999] {
            assert!(
                !approvable_verification_error(code),
                "Hard certificate failure {code} must not become a trust prompt"
            );
        }
    }
}
