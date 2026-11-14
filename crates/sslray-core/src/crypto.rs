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
pub fn connect(profile: &Profile) -> Result<SslStream<TcpStream>> {
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
fn verify_negotiated_crypto(stream: &SslStream<TcpStream>, profile: &Profile) -> Result<()> {
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
fn tcp_connect(profile: &Profile) -> Result<TcpStream> {
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
fn verify_pin(stream: &SslStream<TcpStream>, expected: &str) -> Result<()> {
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

fn certificate_stream(profile: &Profile) -> Result<(SslStream<TcpStream>, Vec<String>)> {
    profile.validate()?;
    certificate_stream_with_connector(profile, connector(profile)?)
}

fn certificate_stream_with_connector(
    profile: &Profile,
    connector: SslConnector,
) -> Result<(SslStream<TcpStream>, Vec<String>)> {
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
    stream: &SslStream<TcpStream>,
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
