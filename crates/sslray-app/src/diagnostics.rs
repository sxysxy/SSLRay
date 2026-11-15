//! Short, localizable error summaries with the original technical detail kept
//! separately. Classification is presentation only, never a trust or retry
//! decision. Known backend errors are already redacted at their source.

use crate::i18n::Language;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticKind {
    Unknown,
    TlsParametersRejected,
    TlsIncompatible,
    TlsHandshake,
    GmUnavailable,
    GmTransport,
    UnknownCertificateAuthority,
    SelfSignedCertificate,
    CertificateExpired,
    CertificateNotYetValid,
    CertificateNameMismatch,
    CertificatePinMismatch,
    CertificateInvalid,
    AuthenticationRejected,
    AuthenticationUnsupported,
    OtpRejected,
    OtpRequired,
    AdministratorAuthorization,
    BiometricAuthorization,
    HelperCommunication,
    Cancelled,
    Timeout,
    DnsResolution,
    ConnectionFailed,
    SessionClosed,
    Routing,
    RouteCleanup,
    VirtualInterface,
    InvalidConfiguration,
    ConfigurationStorage,
    UdpUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic<'a> {
    pub kind: DiagnosticKind,
    pub summary: &'static str,
    /// Original diagnostic, for an explicit expandable/copyable detail view.
    /// Never interpolate this into the short summary or interpret it as a
    /// command, certificate approval, credential rejection, or retry policy.
    pub technical_detail: Option<&'a str>,
}

pub fn describe(language: Language, raw: &str) -> Diagnostic<'_> {
    let kind = classify(raw);
    Diagnostic {
        kind,
        summary: summary(language, kind),
        technical_detail: if raw.trim().is_empty() {
            None
        } else {
            Some(raw)
        },
    }
}

fn starts_with_any(message: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| message.starts_with(prefix))
}

fn numeric_error(message: &str, prefix: &str, suffix: &str) -> bool {
    message
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
        .is_some_and(|value| value.len() <= 20 && value.parse::<i64>().is_ok())
}

fn classify(message: &str) -> DiagnosticKind {
    classify_with_depth(message, 0)
}

fn classify_with_depth(message: &str, depth: u8) -> DiagnosticKind {
    use DiagnosticKind as K;
    if message == "Strict GM TLS mode cannot use AES UDP transport; select TLS or Auto" {
        return K::GmTransport;
    }
    // Error chains from supported backends are shallow. Bound processing of
    // malformed or synthetic nested contexts instead of recursing indefinitely.
    if depth > 4 {
        return K::Unknown;
    }

    if matches!(
        message,
        "Connection cancelled"
            | "Authentication cancelled"
            | "Application is closing"
            | "OpenVPN connection cancelled"
            | "OpenVPN authentication cancelled"
    ) {
        return K::Cancelled;
    }
    let mut authorization_detail = message;
    for _ in 0..4 {
        if let Some(detail) =
            authorization_detail.strip_prefix("Administrator authorization failed: ")
        {
            authorization_detail = detail;
        } else {
            break;
        }
    }
    if authorization_detail == "Administrator biometric authorization not completed"
        || starts_with_any(
            authorization_detail,
            &[
                "Administrator biometric authorization not completed (",
                "Administrator biometric authorization not completed: ",
            ],
        )
    {
        return K::BiometricAuthorization;
    }
    // Prefixes below are emitted by our helper startup code. A timeout while
    // communicating with a helper is not a failed administrator password.
    if matches!(
        message,
        "Administrator authorization failed"
            | "Administrator authorization timed out"
            | "Administrator authorization cancelled"
            | "Starting administrator authorization"
            | "Install polkit/pkexec to request administrator privileges"
            | "Helper requires administrator privileges"
    ) || starts_with_any(
        message,
        &[
            "Administrator authorization failed: ",
            "Administrator authorization/helper failed (",
            "Starting administrator authorization: ",
        ],
    ) {
        return if message.contains("privileged helper") || message.contains("Helper channel") {
            K::HelperCommunication
        } else {
            K::AdministratorAuthorization
        };
    }
    if starts_with_any(
        message,
        &[
            "Reading privileged helper greeting",
            "Checking privileged helper readiness",
            "Configuring privileged helper channel",
            "Privileged helper response timed out",
            "Privileged helper channel closed",
            "Helper channel closed",
            "Helper pool lock failed",
            "Helper state lock failed",
            "Helper event exceeds limit",
            "IPC message exceeds limit",
        ],
    ) || matches!(
        message,
        "Cannot verify helper identity"
            | "Helper peer is not root"
            | "Invalid helper token"
            | "Invalid helper probe response"
    ) {
        return K::HelperCommunication;
    }
    if message == "Gateway certificate SHA-256 mismatch; refusing authentication"
        || matches!(
            message,
            "Gateway identity changed between discovery and authentication"
                | "Gateway identity changed during native SMS authentication"
                | "Cisco gateway identity changed between channels"
                | "Legacy auth and tunnel peer identities differ"
        )
    {
        return K::CertificatePinMismatch;
    }
    if starts_with_any(
        message,
        &[
            "This TLS backend does not support RFC 8998 SM4/SM3 suites",
            "TLS backend does not support the SM2 group",
            "TLS backend does not support SM2/SM3 signatures",
        ],
    ) || matches!(
        message,
        "Gateway did not negotiate a GM cipher"
            | "This OpenVPN backend does not support GM TLS"
            | "OpenVPN does not support the GM TLS mode; select standard cryptography"
    ) {
        return K::GmUnavailable;
    }
    if let Some(detail) = message
        .strip_prefix("TLS certificate preflight failed: ")
        .or_else(|| message.strip_prefix("TLS handshake failed: "))
    {
        return classify_tls(detail);
    }
    // These exact contexts wrap the legacy key/port receive and cmd16 write.
    // Inspect the cause rather than calling every negotiation failure a UDP
    // availability problem: kickout, certificate and TLS failures remain distinct.
    if let Some(detail) = message
        .strip_prefix("Receiving legacy UDP key negotiation: ")
        .or_else(|| message.strip_prefix("Receiving legacy UDP port negotiation: "))
        .or_else(|| message.strip_prefix("Switching legacy UDP transport back to TLS: "))
    {
        return classify_with_depth(detail, depth + 1);
    }
    if let Some(kind) = classify_x509_report(message) {
        return kind;
    }
    if let Some(detail) =
        message.strip_prefix("Native Huawei secondary authentication failed; no automatic retry: ")
    {
        return if primary_rejected(detail)
            || detail
                == "Native Huawei gateway did not accept the verification code; no automatic retry"
        {
            K::OtpRejected
        } else {
            // Certificate/network failures during an OTP exchange must not be
            // presented as a rejected password or rejected verification code.
            classify_with_depth(detail, depth + 1)
        };
    }
    if matches!(
        message,
        "Gateway rejected temporary password"
            | "OpenVPN verification code rejected"
            | "Cisco verification code was rejected; no automatic retry"
            | "Native Huawei gateway did not accept the verification code; no automatic retry"
    ) || numeric_error(message, "Gateway rejected temporary password (status ", ")")
    {
        return K::OtpRejected;
    }
    if matches!(
        message,
        "Gateway requests an SMS/temporary secondary password"
            | "OpenVPN requires a fresh one-time code; reconnect"
            | "No second-password challenge pending"
    ) {
        return K::OtpRequired;
    }
    if primary_rejected(message) {
        return K::AuthenticationRejected;
    }
    if message
        == "Cisco credentials rejected or unsupported additional challenge; no automatic retry"
        || message == "Cisco gateway requires unsupported browser/host-scan authentication"
        || message == "Legacy gateway requires an unsupported certificate authentication method"
        || starts_with_any(
            message,
            &[
                "Native Huawei gateway requires HostID device authentication;",
                "Unsupported gateway secondary authentication method ",
            ],
        )
    {
        return K::AuthenticationUnsupported;
    }
    if starts_with_any(
        message,
        &["Route cleanup failed", "Route rollback failures:"],
    ) {
        return K::RouteCleanup;
    }
    if starts_with_any(
        message,
        &[
            "Route command failed (",
            "Reading original route with ",
            "Could not snapshot original outer route:",
            "Full tunnel requires ",
            "Full tunnel with a non-main policy routing table is not supported",
            "Native route lookup is ambiguous",
            "An unscoped cloned outer host route",
            "Original route ",
            "Original outer route ",
            "Native route response ",
            "Invalid outer IPv4 peer",
            "Invalid original outer gateway",
            "A requested route contains ",
            "Outer peer ",
        ],
    ) || message.starts_with("Route ") && message.ends_with("would create a routing loop")
    {
        return K::Routing;
    }
    if starts_with_any(
        message,
        &[
            "Creating native VPN interface",
            "Setting nonblocking interface I/O",
            "Reading VPN interface name",
            "Loading Wintun from the application directory",
            "Creating Wintun adapter",
            "Configuring Wintun IPv4 address",
            "Configuring Wintun MTU",
            "Starting Wintun session",
            "Place the signed, matching-architecture wintun.dll beside SSLRay",
            "Administrator privileges are required to configure the VPN interface",
        ],
    ) {
        return K::VirtualInterface;
    }
    if message == "Administrator privileges are required to modify routes" {
        return K::Routing;
    }
    if starts_with_any(
        message,
        &[
            "failed to lookup address information:",
            "Failed to resolve gateway",
        ],
    ) || message == "Gateway connection failed: No DNS addresses"
    {
        return K::DnsResolution;
    }
    if starts_with_any(
        message,
        &[
            "Gateway connection failed:",
            "OpenVPN server is unreachable",
        ],
    ) {
        return if contains_timeout(message) {
            K::Timeout
        } else {
            K::ConnectionFailed
        };
    }
    if matches!(
        message,
        "Legacy gateway closed the TLS tunnel"
            | "Legacy gateway terminated the VPN session during negotiation (kickout)"
            | "Legacy gateway terminated the VPN session (kickout)"
            | "Legacy UDP peer stopped responding"
    ) || message
        .strip_prefix("Legacy UDP control channel closed/rejected (command ")
        .and_then(|command| command.strip_suffix(')'))
        .is_some_and(|command| command.parse::<u16>().is_ok())
    {
        return K::SessionClosed;
    }
    if matches!(
        message,
        "TLS handshake timed out"
            | "Gateway handshake timed out"
            | "OpenVPN negotiation timed out"
            | "OpenVPN connection deadline exceeded"
            | "Temporary password challenge timed out"
            | "Cisco CSTP partial frame timed out"
            | "Legacy gateway frame timed out"
    ) || message.starts_with("Legacy gateway handshake timed out (")
    {
        return K::Timeout;
    }
    if starts_with_any(
        message,
        &[
            "Requested UDP fast mode could not be established",
            "This gateway's legacy UDP uses AES-128-CBC without packet authentication.",
            "Legacy UDP negotiation timed out",
        ],
    ) || matches!(
        message,
        "Gateway did not negotiate legacy CHIV UDP mode3"
            | "Missing negotiated legacy UDP port"
            | "Legacy CHIV UDP could not be established"
    ) || message.starts_with("Legacy CHIV UDP could not be established: ")
    {
        return K::UdpUnavailable;
    }
    if starts_with_any(
        message,
        &[
            "Profile storage is unavailable;",
            "Cannot locate the application configuration directory",
            "Invalid configuration directory",
            "Invalid profile library",
            "Invalid legacy profile",
        ],
    ) {
        return K::ConfigurationStorage;
    }
    if matches!(
        message,
        "Invalid gateway host"
            | "Gateway must be a hostname or IP address"
            | "Invalid gateway port"
            | "MTU must be 576..1500"
            | "Invalid username"
            | "Certificate pin must be a SHA-256 fingerprint"
            | "Select an OpenVPN .ovpn configuration file"
            | "Cisco currently supports TLS/CSTP only; select TLS or Auto"
    ) || starts_with_any(
        message,
        &[
            "Invalid IPv4 route ",
            "Route must use IPv4 CIDR",
            "Only split routes with prefixes",
            "Profile name ",
            "A profile with this name already exists",
            "Cannot open an OpenVPN configuration or certificate file",
            "Unsupported OpenVPN ",
            "Invalid OpenVPN ",
        ],
    ) {
        return K::InvalidConfiguration;
    }
    K::Unknown
}

fn primary_rejected(message: &str) -> bool {
    numeric_error(
        message,
        "Native Huawei gateway rejected authentication (status ",
        "); no automatic retry",
    ) || numeric_error(message, "Gateway rejected authentication (status ", ")")
        || matches!(
            message,
            "OpenVPN authentication failed"
                | "Cisco authentication rejected (HTTP 401); no automatic retry"
                | "Cisco authentication rejected (HTTP 403); no automatic retry"
                | "Gateway rejected authentication (legacy ReloginCause unknown); no automatic retry"
        )
        || numeric_error(
            message,
            "Gateway rejected authentication (legacy ReloginCause ",
            "); no automatic retry",
        )
}

fn contains_timeout(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("timed out") || lower.contains("timeout")
}

fn classify_tls(detail: &str) -> DiagnosticKind {
    use DiagnosticKind as K;
    let lower = detail.to_ascii_lowercase();
    if lower.contains("illegal_parameter") || lower.contains("illegal parameter") {
        K::TlsParametersRejected
    } else if lower.contains("self-signed certificate") || lower.contains("self signed certificate")
    {
        K::SelfSignedCertificate
    } else if lower.contains("certificate has expired") || lower.contains("certificate expired") {
        K::CertificateExpired
    } else if lower.contains("certificate is not yet valid") {
        K::CertificateNotYetValid
    } else if lower.contains("hostname mismatch") || lower.contains("ip address mismatch") {
        K::CertificateNameMismatch
    } else if lower.contains("unable to get local issuer certificate")
        || lower.contains("unable to get issuer certificate")
        || lower.contains("unable to verify the first certificate")
        || lower.contains("unknown ca")
        || lower.contains("unknown_ca")
    {
        K::UnknownCertificateAuthority
    } else if lower.contains("certificate verify failed")
        || lower.contains("certificate revoked")
        || lower.contains("certificate signature failure")
    {
        K::CertificateInvalid
    } else if contains_timeout(detail) {
        K::Timeout
    } else if lower.contains("protocol version")
        || lower.contains("protocol_version")
        || lower.contains("unsupported protocol")
        || lower.contains("wrong version number")
        || lower.contains("no shared cipher")
        || lower.contains("handshake failure")
    {
        K::TlsIncompatible
    } else {
        K::TlsHandshake
    }
}

/// Recognize only the exact structured X509 report shape produced by core.
/// A server message merely mentioning one of these words stays Unknown.
fn classify_x509_report(message: &str) -> Option<DiagnosticKind> {
    use DiagnosticKind as K;
    let (reason, location) = message.split_once(" (code ")?;
    let (code, depth) = location.strip_suffix(')')?.split_once(", depth ")?;
    if depth.parse::<u32>().is_err() {
        return None;
    }
    match (reason, code) {
        ("self-signed certificate", "18")
        | ("self-signed certificate in certificate chain", "19") => Some(K::SelfSignedCertificate),
        ("certificate has expired", "10") => Some(K::CertificateExpired),
        ("certificate is not yet valid", "9") => Some(K::CertificateNotYetValid),
        ("hostname mismatch", "62") | ("IP address mismatch", "64") => {
            Some(K::CertificateNameMismatch)
        }
        ("unable to get issuer certificate", "2")
        | ("unable to get local issuer certificate", "20")
        | ("unable to verify the first certificate", "21")
        | ("certificate not trusted", "27") => Some(K::UnknownCertificateAuthority),
        _ => None,
    }
}

fn summary(language: Language, kind: DiagnosticKind) -> &'static str {
    use DiagnosticKind as K;
    let (zh, en) = match kind {
        K::Unknown => (
            "操作未完成，请展开技术详情查看原因。",
            "The operation could not be completed. Expand technical details for the cause.",
        ),
        K::TlsParametersRejected => (
            "网关拒绝了 TLS 协商参数。请核对加密设置；使用国密时，需确认网关支持该模式。",
            "The gateway rejected TLS parameters. Check encryption settings; GM TLS requires gateway support.",
        ),
        K::TlsIncompatible => (
            "TLS 协议或算法未能协商，请核对网关与加密设置。",
            "TLS protocol or cipher negotiation failed. Check the gateway and encryption settings.",
        ),
        K::TlsHandshake => (
            "TLS 握手未完成，请核对网关及证书设置。",
            "The TLS handshake failed. Check the gateway and certificate settings.",
        ),
        K::GmTransport => (
            "国密模式仅支持 TLS 传输，请选择 TLS 或自适应。",
            "GM mode requires TLS transport. Select TLS or adaptive mode.",
        ),
        K::GmUnavailable => (
            "所选国密配置不可用。请核对网关和加密后端，不会自动降级。",
            "The selected GM TLS configuration is unavailable. Check the gateway and TLS backend; no downgrade is attempted.",
        ),
        K::UnknownCertificateAuthority => (
            "证书签发机构未被信任，请向管理员核对证书链和指纹。",
            "The certificate issuer is not trusted. Verify the chain and fingerprint with your administrator.",
        ),
        K::SelfSignedCertificate => (
            "证书链包含自签名证书，请向管理员核对指纹。",
            "The certificate chain contains a self-signed certificate. Verify its fingerprint with your administrator.",
        ),
        K::CertificateExpired => (
            "证书已过期，请联系管理员更新。",
            "The certificate has expired. Contact your administrator for a replacement.",
        ),
        K::CertificateNotYetValid => (
            "证书尚未生效，请核对系统时间并联系管理员。",
            "The certificate is not yet valid. Check the system clock and contact your administrator.",
        ),
        K::CertificateNameMismatch => (
            "证书与网关地址不匹配，请核对地址及指纹。",
            "The certificate does not match the gateway address. Verify the address and fingerprint.",
        ),
        K::CertificatePinMismatch => (
            "证书与预期指纹不符，已停止连接。请向管理员核实；不会自动替换指纹。",
            "The certificate does not match the expected fingerprint. Connection stopped; the pin will not be replaced automatically.",
        ),
        K::CertificateInvalid => (
            "证书校验失败，已停止连接。请联系管理员。",
            "Certificate verification failed. Connection stopped; contact your administrator.",
        ),
        K::AuthenticationRejected => (
            "网关拒绝了登录，请核对账号、密码及账号状态。",
            "The gateway rejected sign-in. Check your username, password and account status.",
        ),
        K::AuthenticationUnsupported => (
            "网关要求尚未支持的认证方式，请核对网关设置。",
            "The gateway requires an unsupported authentication method. Check its settings.",
        ),
        K::OtpRejected => (
            "网关拒绝了临时密码或验证码，请获取新验证码后重试。",
            "The gateway rejected the temporary password or code. Obtain a fresh code and try again.",
        ),
        K::OtpRequired => (
            "网关需要新的临时密码或验证码，请重新输入。",
            "The gateway requires a fresh temporary password or verification code.",
        ),
        K::AdministratorAuthorization => (
            "系统授权或网络助手启动未完成，请查看系统提示后重试。",
            "Administrator authorization or helper startup did not complete. Check the system prompt and try again.",
        ),
        K::BiometricAuthorization => (
            "指纹授权未完成。可以重试，或选择“使用密码授权”。",
            "Touch ID authorization did not complete. Retry or choose Authorize with password.",
        ),
        K::HelperCommunication => (
            "无法与网络助手通信，请重试连接并查看技术详情。",
            "Could not communicate with the network helper. Retry the connection and check technical details.",
        ),
        K::Cancelled => (
            "连接操作已取消。",
            "The connection operation was cancelled.",
        ),
        K::Timeout => (
            "连接等待超时，请检查网络和网关后重试。",
            "The connection timed out. Check your network and gateway, then try again.",
        ),
        K::DnsResolution => (
            "无法解析网关地址，请检查地址及 DNS 设置。",
            "Could not resolve the gateway address. Check the address and DNS settings.",
        ),
        K::ConnectionFailed => (
            "无法连接网关，请检查网络、地址和端口。",
            "Could not reach the gateway. Check your network, gateway address and port.",
        ),
        K::SessionClosed => (
            "VPN 会话已断开，请检查网关会话及网络状态后重新连接。",
            "The VPN session was closed. Check the gateway session and network before reconnecting.",
        ),
        K::Routing => (
            "无法应用 VPN 路由，请检查权限及路由冲突。",
            "Could not apply VPN routes. Check permissions and route conflicts.",
        ),
        K::RouteCleanup => (
            "部分 VPN 路由未能清理，请查看详情确认网络状态。",
            "Some VPN routes could not be removed. Check technical details and the network state.",
        ),
        K::VirtualInterface => (
            "无法创建或配置虚拟网卡，请检查系统权限和驱动。",
            "Could not create or configure the tunnel adapter. Check system permissions and drivers.",
        ),
        K::InvalidConfiguration => (
            "连接配置无效，请检查设置。",
            "The connection configuration is invalid. Check your settings.",
        ),
        K::ConfigurationStorage => (
            "无法读取或保存本地配置，请检查文件及权限。",
            "Could not read or save the local configuration. Check the file and its permissions.",
        ),
        K::UdpUnavailable => (
            "UDP 快速通道未能建立，请检查网关支持或选择 TLS。",
            "The fast UDP channel could not be established. Check gateway support or select TLS.",
        ),
    };
    match language {
        Language::ZhCn => zh,
        Language::En => en,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn biometric_errors_are_localized_without_claiming_wrong_password() {
        for raw in [
            "Administrator biometric authorization not completed",
            "Administrator biometric authorization not completed (exit status: 1): sudo failed",
            "Administrator authorization failed: Administrator authorization failed: Administrator biometric authorization not completed: access denied",
        ] {
            for language in [Language::ZhCn, Language::En] {
                let diagnostic = describe(language, raw);
                assert_eq!(diagnostic.kind, DiagnosticKind::BiometricAuthorization);
                assert_eq!(diagnostic.technical_detail, Some(raw));
                assert!(!diagnostic.summary.contains("wrong password"));
                assert!(!diagnostic.summary.contains("密码错误"));
            }
        }
        assert_eq!(
            describe(
                Language::En,
                "server says Administrator biometric authorization not completed"
            )
            .kind,
            DiagnosticKind::Unknown,
        );
    }

    #[test]
    fn tls_parameter_alert_has_a_short_localized_summary_and_intact_details() {
        let raw = "TLS certificate preflight failed: error:0A000417:SSL routines:ssl3_read_bytes:ssl/tls alert illegal parameter:ssl/record/rec_layer_s3.c:916:SSL alert number 47";
        for language in [Language::ZhCn, Language::En] {
            let diagnostic = describe(language, raw);
            assert_eq!(diagnostic.kind, DiagnosticKind::TlsParametersRejected);
            assert_eq!(diagnostic.technical_detail, Some(raw));
            assert!(!diagnostic.summary.contains("rec_layer_s3"));
            assert!(diagnostic.summary.chars().count() < 150);
        }
        assert!(describe(Language::ZhCn, raw).summary.contains("国密"));
        assert!(describe(Language::En, raw).summary.contains("GM TLS"));
    }

    #[test]
    fn recognized_tls_and_structured_x509_errors_have_specific_summaries() {
        for (reason, code, expected) in [
            (
                "self-signed certificate",
                18,
                DiagnosticKind::SelfSignedCertificate,
            ),
            (
                "unable to get local issuer certificate",
                20,
                DiagnosticKind::UnknownCertificateAuthority,
            ),
            (
                "certificate has expired",
                10,
                DiagnosticKind::CertificateExpired,
            ),
            (
                "certificate is not yet valid",
                9,
                DiagnosticKind::CertificateNotYetValid,
            ),
            (
                "hostname mismatch",
                62,
                DiagnosticKind::CertificateNameMismatch,
            ),
        ] {
            let report = format!("{reason} (code {code}, depth 0)");
            assert_eq!(describe(Language::En, &report).kind, expected);
            let tls = format!("TLS handshake failed: certificate verify failed: {reason}");
            assert_eq!(describe(Language::ZhCn, &tls).kind, expected);
        }
    }

    #[test]
    fn pin_mismatch_does_not_suggest_replacing_a_saved_pin() {
        let diagnostic = describe(
            Language::En,
            "Gateway certificate SHA-256 mismatch; refusing authentication",
        );
        assert_eq!(diagnostic.kind, DiagnosticKind::CertificatePinMismatch);
        assert!(diagnostic.summary.contains("not be replaced automatically"));
    }

    #[test]
    fn legacy_udp_negotiation_failures_have_short_summaries_and_original_details() {
        for raw in [
            "Gateway did not negotiate legacy CHIV UDP mode3",
            "Missing negotiated legacy UDP port",
            "Legacy CHIV UDP could not be established: Legacy UDP requires an IPv4 gateway and negotiated port",
            "Legacy CHIV UDP could not be established: Legacy CHIV UDP probe timed out; received 0 datagrams; last shape: none; select TLS transport",
            "Receiving legacy UDP key negotiation: Legacy UDP negotiation timed out: Legacy gateway handshake timed out (0 buffered frame bytes)",
            "Receiving legacy UDP port negotiation: Legacy UDP negotiation timed out: Legacy gateway handshake timed out (0 buffered frame bytes)",
        ] {
            for language in [Language::ZhCn, Language::En] {
                let diagnostic = describe(language, raw);
                assert_eq!(diagnostic.kind, DiagnosticKind::UdpUnavailable);
                assert_eq!(diagnostic.technical_detail, Some(raw));
                assert!(!diagnostic.summary.contains("buffered"));
                assert!(diagnostic.summary.chars().count() < 150);
            }
        }
    }

    #[test]
    fn legacy_session_termination_is_not_reported_as_failed_udp_establishment() {
        for raw in [
            "Legacy UDP control channel closed/rejected (command 8)",
            "Legacy UDP control channel closed/rejected (command 65535)",
            "Legacy gateway closed the TLS tunnel",
            "Legacy gateway terminated the VPN session (kickout)",
            "Receiving legacy UDP key negotiation: Legacy gateway terminated the VPN session during negotiation (kickout)",
            "Receiving legacy UDP port negotiation: Legacy gateway closed the TLS tunnel",
            "Legacy UDP peer stopped responding",
        ] {
            for language in [Language::ZhCn, Language::En] {
                let diagnostic = describe(language, raw);
                assert_eq!(diagnostic.kind, DiagnosticKind::SessionClosed);
                assert_eq!(diagnostic.technical_detail, Some(raw));
                assert!(!diagnostic.summary.contains("could not be established"));
                assert!(!diagnostic.summary.contains("未能建立"));
            }
        }
        for invalid in ["-1", "65536", "synthetic-password"] {
            let raw = format!("Legacy UDP control channel closed/rejected (command {invalid})");
            assert_eq!(describe(Language::En, &raw).kind, DiagnosticKind::Unknown);
        }
    }

    #[test]
    fn legacy_negotiation_context_does_not_hide_tls_or_identity_failures() {
        for (raw, expected) in [
            (
                "Legacy auth and tunnel peer identities differ",
                DiagnosticKind::CertificatePinMismatch,
            ),
            (
                "Receiving legacy UDP key negotiation: TLS handshake failed: certificate verify failed: certificate has expired",
                DiagnosticKind::CertificateExpired,
            ),
            (
                "Receiving legacy UDP port negotiation: Gateway certificate SHA-256 mismatch; refusing authentication",
                DiagnosticKind::CertificatePinMismatch,
            ),
            (
                "Switching legacy UDP transport back to TLS: TLS handshake failed: ssl/tls alert illegal parameter",
                DiagnosticKind::TlsParametersRejected,
            ),
            (
                "Receiving legacy UDP key negotiation: Reading legacy Huawei TLS tunnel: Connection reset by peer (os error 54)",
                DiagnosticKind::Unknown,
            ),
        ] {
            let diagnostic = describe(Language::En, raw);
            assert_eq!(diagnostic.kind, expected);
            assert_ne!(diagnostic.kind, DiagnosticKind::AuthenticationRejected);
            assert_ne!(diagnostic.kind, DiagnosticKind::UdpUnavailable);
            assert_eq!(diagnostic.technical_detail, Some(raw));
        }
        assert_eq!(
            describe(
                Language::En,
                "Strict GM TLS mode cannot use AES UDP transport; select TLS or Auto",
            )
            .kind,
            DiagnosticKind::GmTransport,
        );
    }

    #[test]
    fn primary_rejection_secondary_rejection_and_secondary_tls_failure_are_distinct() {
        for (raw, expected) in [
            (
                "Native Huawei gateway rejected authentication (status -100); no automatic retry",
                DiagnosticKind::AuthenticationRejected,
            ),
            (
                "OpenVPN authentication failed",
                DiagnosticKind::AuthenticationRejected,
            ),
            (
                "Gateway rejected temporary password (status 2)",
                DiagnosticKind::OtpRejected,
            ),
            (
                "OpenVPN verification code rejected",
                DiagnosticKind::OtpRejected,
            ),
            (
                "Native Huawei secondary authentication failed; no automatic retry: Native Huawei gateway rejected authentication (status -100); no automatic retry",
                DiagnosticKind::OtpRejected,
            ),
            (
                "Native Huawei secondary authentication failed; no automatic retry: TLS handshake failed: certificate verify failed: certificate has expired",
                DiagnosticKind::CertificateExpired,
            ),
        ] {
            assert_eq!(describe(Language::En, raw).kind, expected);
        }
    }

    #[test]
    fn helper_and_network_and_routing_failures_keep_their_contexts() {
        for (raw, expected) in [
            (
                "Administrator authorization failed: user cancelled",
                DiagnosticKind::AdministratorAuthorization,
            ),
            (
                "Administrator authorization failed: Reading privileged helper greeting: Privileged helper response timed out",
                DiagnosticKind::HelperCommunication,
            ),
            (
                "failed to lookup address information: nodename nor servname provided",
                DiagnosticKind::DnsResolution,
            ),
            (
                "Gateway connection failed: Connection refused (os error 61)",
                DiagnosticKind::ConnectionFailed,
            ),
            (
                "Gateway connection failed: connection timed out",
                DiagnosticKind::Timeout,
            ),
            (
                "Route command failed (exit status: 1): File exists",
                DiagnosticKind::Routing,
            ),
            (
                "Route cleanup failed: synthetic failure",
                DiagnosticKind::RouteCleanup,
            ),
            (
                "Creating native VPN interface: Permission denied",
                DiagnosticKind::VirtualInterface,
            ),
        ] {
            assert_eq!(describe(Language::En, raw).kind, expected);
        }
    }

    #[test]
    fn arbitrary_server_text_cannot_spoof_a_recognized_error_or_enter_the_summary() {
        for raw in [
            "server says certificate has expired; password=synthetic-secret",
            "server error: TLS handshake failed: unknown ca",
            "server says self-signed certificate (code 18, depth 0)",
            "Gateway rejected authentication (status password=synthetic-secret)",
            "Administrator authorization failed for gateway account",
            "server says Legacy auth and tunnel peer identities differ",
            "server says Gateway did not negotiate legacy CHIV UDP mode3",
        ] {
            for language in [Language::ZhCn, Language::En] {
                let diagnostic = describe(language, raw);
                assert_eq!(diagnostic.kind, DiagnosticKind::Unknown);
                assert_eq!(diagnostic.technical_detail, Some(raw));
                assert!(!diagnostic.summary.contains("synthetic-secret"));
                assert!(!diagnostic.summary.contains(raw));
            }
        }
    }

    #[test]
    fn unknown_huge_or_empty_details_do_not_change_the_fixed_summary() {
        let raw = "synthetic-unclassified-detail".repeat(10_000);
        let diagnostic = describe(Language::En, &raw);
        assert_eq!(diagnostic.kind, DiagnosticKind::Unknown);
        assert_eq!(diagnostic.technical_detail, Some(raw.as_str()));
        assert!(diagnostic.summary.len() < 150);
        assert_eq!(describe(Language::ZhCn, " \n").technical_detail, None);
    }

    #[test]
    fn deeply_nested_contexts_are_bounded_and_gm_backend_failure_never_suggests_downgrade() {
        let raw = "Native Huawei secondary authentication failed; no automatic retry: "
            .repeat(1_000)
            + "OpenVPN authentication failed";
        assert_eq!(describe(Language::En, &raw).kind, DiagnosticKind::Unknown);
        let raw = "TLS backend does not support the SM2 group: synthetic backend error";
        let diagnostic = describe(Language::En, raw);
        assert_eq!(diagnostic.kind, DiagnosticKind::GmUnavailable);
        assert!(diagnostic.summary.contains("no downgrade"));
        assert_eq!(diagnostic.technical_detail, Some(raw));
    }
}
