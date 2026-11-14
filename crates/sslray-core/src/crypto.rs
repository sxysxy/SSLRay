//! TLS policy shared by both Huawei channels. No implicit insecure fallback.
use crate::config::{CryptoMode, Profile};
use anyhow::{Context, Result, bail, ensure};
use openssl::{
    hash::MessageDigest,
    ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode, SslVersion},
};
use serde::Serialize;
use std::{
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

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
    Ok(stream)
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
/// Certificate discovery sends no application data or credentials. This is not trust approval.
pub fn inspect(profile: &Profile) -> Result<serde_json::Value> {
    profile.validate()?;
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_verify(SslVerifyMode::NONE);
    let mut config = builder.build().configure()?;
    config.set_verify_hostname(false);
    let stream = config
        .connect(&profile.host, tcp_connect(profile)?)
        .map_err(|e| anyhow::anyhow!("TLS discovery failed: {e}"))?;
    let cert = stream
        .ssl()
        .peer_certificate()
        .context("Missing certificate")?;
    Ok(serde_json::json!({
        "host": profile.host, "port": profile.port,
        "certificate_sha256": hex::encode(cert.digest(MessageDigest::sha256())?),
        "subject": format!("{:?}", cert.subject_name()), "issuer": format!("{:?}", cert.issuer_name()),
        "not_after": cert.not_after().to_string(), "tls": stream.ssl().version_str(),
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
}
