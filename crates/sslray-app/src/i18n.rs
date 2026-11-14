//! UI and tray text catalog. Diagnostic details returned by a gateway remain intact.
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Language {
    #[default]
    #[serde(rename = "zh-CN")]
    ZhCn,
    #[serde(rename = "en")]
    En,
}
impl Language {
    pub fn label(self) -> &'static str {
        match self {
            Self::ZhCn => "简体中文",
            Self::En => "English",
        }
    }
}

macro_rules! catalog {
    ($( $id:ident => ($zh:literal, $en:literal), )*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Text { $( $id, )* }
        pub fn text(language: Language, id: Text) -> &'static str {
            match (language, id) {
                $( (Language::ZhCn, Text::$id) => $zh,
                   (Language::En, Text::$id) => $en, )*
            }
        }
    };
}
catalog! {
    TrayUnavailable => ("系统托盘不可用，关闭窗口会退出", "System tray unavailable; closing the window exits SSLRay"),
    ConfigDirectoryUnavailable => ("无法定位应用配置目录", "Cannot locate the application configuration directory"),
    InputCredentials => ("请输入用户名和密码。", "Enter your username and password."),
    ConnectFailed => ("连接失败", "Connection failed"),
    InvalidProfile => ("配置无效", "Invalid connection configuration"),
    Tagline => ("安全，连接每一个工作现场", "Secure access, wherever you work"),
    Overview => ("连接概览", "Overview"),
    Settings => ("连接设置", "Settings"),
    AppSettings => ("软件设置", "Application settings"),
    AppSettingsSubtitle => ("设置外观，查看 SSLRay 网卡和软件信息。", "Set appearance and view the SSLRay adapter and application information."),
    Appearance => ("外观", "Appearance"),
    About => ("关于软件", "About"),
    Version => ("软件版本", "Version"),
    Platform => ("运行平台", "Platform"),
    AdapterInfo => ("SSLRay 网络适配器", "SSLRay network adapter"),
    Refresh => ("刷新", "Refresh"),
    Loading => ("正在读取…", "Loading…"),
    AdapterName => ("适配器", "Adapter"),
    AdapterAddresses => ("IP 地址", "IP addresses"),
    AdapterUp => ("已启用", "Up"),
    AdapterDown => ("未启用", "Down"),
    NoAdapters => ("尚未创建 SSLRay 网卡，连接后会在这里显示。", "No SSLRay adapter has been created. It will appear here after connecting."),
    AdapterReadFailed => ("未能读取 SSLRay 网卡的完整信息", "Could not read complete SSLRay adapter information"),
    AdapterSnapshotOnly => ("以下为当前会话已知信息，尚未读取完整系统状态。", "These values come from the current session; complete system status is unavailable."),
    ConfiguredMtu => ("配置 MTU（非实测值）", "Configured MTU (not measured)"),
    AdapterCleanupUnconfirmed => ("会话已停止，部分路由清理尚未确认，请查看日志。", "The session has stopped. Cleanup of some routes is unconfirmed; check the log."),
    TunnelAdapter => ("虚拟网卡", "Tunnel adapter"),
    Browse => ("选择文件…", "Browse…"),
    OvpnDialogTitle => ("选择 OpenVPN 配置文件", "Choose an OpenVPN configuration file"),
    Authorization => ("管理员授权", "Administrator authorization"),
    AuthorizationFailed => ("管理员授权未完成", "Administrator authorization not completed"),
    RetryAuthorization => ("重新申请授权", "Retry administrator authorization"),
    AuthorizationRetryHelp => ("请在系统弹窗中完成管理员授权；取消或失败后可以重试。", "Complete administrator authorization in the system dialog. You can retry after cancellation or failure."),
    AuthorizationWindowsHelp => ("Windows 使用 UAC 提升权限。", "Windows uses UAC elevation."),
    AuthorizationLinuxHelp => ("Linux 使用 polkit / pkexec，需要桌面认证代理；无图形代理时请在终端运行。", "Linux uses polkit / pkexec and requires a desktop authentication agent; use the terminal if no graphical agent is available."),
    AuthorizationMacHelp => ("macOS 使用系统管理员授权弹窗。", "macOS uses the system administrator authorization dialog."),
    Logs => ("运行日志", "Session log"),
    HideToTray => ("收起到系统托盘  ↗", "Hide to system tray  ↗"),
    DesktopClient => ("桌面客户端", "DESKTOP CLIENT"),
    Connected => ("已安全连接", "Securely connected"),
    Connecting => ("正在建立连接", "Connecting"),
    AwaitingOtp => ("等待第二密码验证", "Second password required"),
    Disconnecting => ("正在断开连接", "Disconnecting"),
    Failed => ("连接未成功", "Connection failed"),
    Ready => ("准备好安全连接", "Ready to connect"),
    TunnelEstablished => ("专属加密隧道已建立", "Your encrypted tunnel is ready"),
    TunnelDescription => ("通过加密隧道访问企业网络", "Access your company network securely"),
    Disconnect => ("断开连接", "Disconnect"),
    CancelConnect => ("取消连接", "Cancel connection"),
    Connect => ("连接 VPN  →", "Connect VPN  →"),
    VirtualIp => ("虚拟 IP", "Virtual IP"),
    Interface => ("网络接口", "Interface"),
    Upload => ("上传流量", "Uploaded"),
    SentEncrypted => ("经加密隧道发送", "Sent through the encrypted tunnel"),
    Download => ("下载流量", "Downloaded"),
    ConnectedTime => ("连接时长", "Connected for"),
    Credentials => ("连接凭据", "Credentials"),
    PasswordSessionOnly => ("密码仅在本次会话中使用", "Passwords stay in this session"),
    RememberPassword => ("保存主密码到本地", "Save main password locally"),
    PlaintextPasswordWarning => ("主密码将以 Base64 编码保存在以下本地文件，不会上传云端。Base64 可还原且不是加密，请注意防止泄露。", "Your main password will be stored as Base64 in this local file and will not be uploaded to the cloud. Base64 is reversible, not encryption; prevent disclosure."),
    ConfirmSavePassword => ("确认保存主密码", "Confirm main password storage"),
    Confirm => ("确认", "Confirm"),
    PasswordRequiredTitle => ("输入连接密码", "Enter connection password"),
    PasswordForProfile => ("当前连接配置", "Connection profile"),
    PasswordRejected => ("网关明确拒绝了登录凭据，请重新输入密码。", "The gateway rejected the login credentials. Enter your password again."),
    ContinueConnect => ("继续连接", "Continue connection"),
    PasswordNotSaved => ("本次密码仅用于连接，不会保存。", "This password is used for this connection only and will not be saved."),
    SavedPasswordRemoved => ("已清除失效的已保存密码。", "The rejected saved password has been removed."),
    PasswordMissingForSave => ("请先输入要保存的密码。", "Enter the password to save."),
    InvalidSavedPassword => ("保存的密码须为 1–1024 字节，且不能包含空字符。", "Saved passwords must be 1–1024 bytes and contain no null characters."),
    SavePasswordUnavailable => ("无法定位本地配置文件，不能保存密码。", "The local configuration file could not be located; password saving is unavailable."),
    ProfileStorageBlocked => ("配置文件读取失败，已禁止覆盖；请先修复配置文件。", "The profile file could not be read. Fix it before saving changes."),
    Username => ("用户名", "Username"),
    UsernameHint => ("输入企业账号", "Enter your company account"),
    Password => ("密码", "Password"),
    PasswordHint => ("输入登录密码", "Enter your password"),
    UseOtp => ("使用第二临时密码 / OTP", "Use a temporary second password / OTP"),
    ShowPassword => ("显示密码", "Show password"),
    HidePassword => ("隐藏密码", "Hide password"),
    OtpHint => ("本次验证码 / 第二密码", "Current code / second password"),
    OtpSeparate => ("第二密码独立提交，不会拼接到主密码。", "The second password is submitted separately from your password."),
    AutoMode => ("自适应模式", "Adaptive mode"),
    TlsMode => ("可靠 TLS 模式", "Reliable TLS mode"),
    UdpMode => ("UDP 快速模式 · 实验性", "Fast UDP mode · experimental"),
    StandardCrypto => ("标准加密", "Standard encryption"),
    GmTls13 => ("国密 TLS 1.3", "GM TLS 1.3"),
    ActualTransport => ("当前传输", "Active transport"),
    ConnectionProfile => ("接入配置", "Connection profile"),
    SelectProfile => ("连接配置", "Connection profile"),
    ManageProfiles => ("管理配置", "Manage profiles"),
    NewProfile => ("新建", "New"),
    DuplicateProfile => ("复制", "Duplicate"),
    DeleteProfile => ("删除", "Delete"),
    NewProfileName => ("新建连接", "New connection"),
    DuplicateNameSuffix => ("副本", "Copy"),
    ProfileChanged => ("已切换连接配置。", "Connection profile selected."),
    ProfileCreated => ("已新建连接配置，请编辑后保存。", "New profile created. Edit it and save."),
    ProfileDeleted => ("已删除连接配置。", "Connection profile deleted."),
    UnsavedChanges => ("有未保存的修改", "Unsaved changes"),
    UnsavedProfilePrompt => ("当前配置有未保存的修改，保存后继续，或放弃这些修改。", "This profile has unsaved changes. Save to continue, or discard the changes."),
    SaveAndContinue => ("保存并继续", "Save and continue"),
    DiscardChanges => ("放弃修改", "Discard changes"),
    Cancel => ("取消", "Cancel"),
    DeleteProfileTitle => ("删除连接配置", "Delete connection profile"),
    DeleteProfilePrompt => ("删除此配置后无法在应用中恢复。", "This profile cannot be restored in the app after deletion."),
    LastProfileHelp => ("至少保留一个连接配置。", "Keep at least one connection profile."),
    DisconnectToSwitch => ("断开连接后可切换或管理配置。", "Disconnect to switch or manage profiles."),
    ReadProfilesFailed => ("无法读取配置列表", "Could not read connection profiles"),
    ProfileActionFailed => ("配置操作失败", "Profile operation failed"),
    ProfileNameRequired => ("请输入连接名称。", "Enter a connection name."),
    ProfileNameTooLong => ("连接名称最多 80 个字符。", "Connection names must be at most 80 characters."),
    InvalidProfileName => ("连接名称不能包含控制字符。", "Connection names cannot contain control characters."),
    DuplicateProfileName => ("该连接名称已存在，请使用不同的名称。", "This connection name already exists. Choose another name."),
    PreparedOpenVpnNotSavable => ("不能保存包含临时证书或私钥的 OpenVPN 配置，请使用 .ovpn 文件路径。", "An OpenVPN configuration containing temporary certificates or private keys cannot be saved. Use an .ovpn file path."),
    SaveProfile => ("保存配置", "Save profile"),
    ProfileSaved => ("已保存连接配置。临时密码不会保存。", "Connection profile saved. Temporary passwords are never saved."),
    SaveFailed => ("保存失败", "Could not save configuration"),
    Protocol => ("VPN 协议", "VPN protocol"),
    ProtocolHuawei => ("华为 SecoClient / UniVPN", "Huawei SecoClient / UniVPN"),
    ProtocolCisco => ("Cisco AnyConnect", "Cisco AnyConnect"),
    ProtocolOpenVpn => ("OpenVPN", "OpenVPN"),
    OvpnConfig => ("OpenVPN 配置文件（.ovpn）", "OpenVPN configuration (.ovpn)"),
    OvpnPathHint => ("输入 .ovpn 文件路径", "Enter the .ovpn file path"),
    OvpnPathRequired => ("请填写 OpenVPN .ovpn 配置文件路径。", "Enter the path to an OpenVPN .ovpn configuration file."),
    OvpnConfigHelp => ("从 .ovpn 加载服务器、CA、客户端证书和私钥；配置中只保存该文件路径。登录密码仅在选择本地保存后写入配置文件。", "Server, CA, client certificate and private key settings are loaded from .ovpn; the profile keeps only that file path. Login passwords are written to the profile only when local saving is selected."),
    OvpnCredentialsHelp => ("证书认证可留空用户名和密码；使用 auth-user-pass 时请填写网关要求的账号。", "Username and password may be empty for certificate authentication. For auth-user-pass, provide the credentials required by the gateway."),
    OvpnAutoOption => ("自动（遵循 .ovpn proto）", "Auto · follow .ovpn proto"),
    OvpnTcpOption => ("TCP 传输", "TCP transport"),
    OvpnUdpOption => ("UDP 传输", "UDP transport"),
    OvpnTransportHelp => ("OpenVPN 自动模式使用 .ovpn 中的 proto 设置；可显式选择 TCP 或 UDP。", "OpenVPN Auto follows the proto directive in .ovpn; TCP or UDP can also be selected explicitly."),
    OvpnGmUnsupported => ("OpenVPN 目前不支持国密 TLS 模式，请选择标准加密。", "OpenVPN does not currently support GM TLS mode. Select standard encryption."),
    CiscoAutoOption => ("自动（TLS / CSTP）", "Auto · TLS / CSTP"),
    CiscoTlsOption => ("TLS / CSTP", "TLS / CSTP"),
    CiscoUdpUnsupported => ("UDP / DTLS 暂不支持", "UDP / DTLS is not yet supported"),
    CiscoTransportHelp => ("Cisco AnyConnect 当前只使用 TLS / CSTP，自动模式也选择 TLS；UDP / DTLS 尚未实现。", "Cisco AnyConnect currently uses TLS / CSTP only, including in Auto mode. UDP / DTLS is not implemented yet."),
    ProfileName => ("连接名称", "Connection name"),
    GatewayHost => ("网关地址", "Gateway address"),
    Port => ("端口", "Port"),
    Transport => ("传输模式", "Transport mode"),
    AutoOption => ("自适应（优先可用传输）", "Adaptive · prefer available UDP"),
    TlsOption => ("可靠模式 · TLS / TCP", "Reliable · TLS / TCP"),
    UdpOption => ("快速模式 · UDP（实验性）", "Fast · UDP (experimental)"),
    UdpTooltip => ("实验性 Huawei UDP，需要网关支持；严格快速模式失败不会回退 TLS。", "Experimental Huawei UDP requires gateway support. Strict fast mode does not fall back to TLS."),
    CryptoPolicy => ("加密配置", "Encryption policy"),
    StandardTls => ("标准 TLS", "Standard TLS"),
    GmOption => ("国密 TLS 1.3 · SM2 / SM3 / SM4", "GM TLS 1.3 · SM2 / SM3 / SM4"),
    GmTooltip => ("需要兼容的加密后端与网关共同支持国密 TLS 1.3。", "Requires GM TLS 1.3 support in both the linked cryptographic backend and the gateway."),
    AllowLegacyUdp => ("允许旧版华为 UDP 兼容模式（实验性）", "Allow legacy Huawei UDP compatibility (experimental)"),
    LegacyUdpTooltip => ("旧版 CHIV UDP 使用 AES-128-CBC，但没有逐包 MAC。本兼容模式仅允许 CHIV3，不使用默认 IV 的 CHIV2。默认关闭；自适应模式遇到旧版网关时保持 TLS。GCMv1 的认证传输不受此选项影响。", "Legacy CHIV UDP uses AES-128-CBC without a per-datagram MAC. Compatibility permits CHIV3 only, never default-IV CHIV2. Disabled by default: adaptive mode keeps TLS for legacy gateways. Authenticated GCMv1 is unaffected."),
    LegacyUdpWarning => ("已允许旧版 CHIV3 / AES-128-CBC UDP。该华为协议缺少数据报 MAC，无法提供逐包完整性认证。关闭此选项可继续使用 TLS；GCMv1 的认证模式不受影响。", "Legacy CHIV3 / AES-128-CBC UDP is enabled. This Huawei protocol has no datagram MAC and cannot authenticate each packet’s integrity. Disable it to retain TLS; authenticated GCMv1 is unaffected."),
    TransportCryptoHelp => ("自适应优先认证 UDP，失败时回退 TLS，默认对旧版网关保持 TLS。国密配置需要兼容的加密后端与网关共同支持，不会自动降级。", "Adaptive mode prefers authenticated UDP, falls back to TLS, and keeps TLS for legacy gateways by default. GM requires a compatible backend and gateway; it never silently downgrades."),
    CryptoBackend => ("当前加密后端", "Cryptographic backend"),
    Available => ("可用", "available"),
    Unavailable => ("不可用", "unavailable"),
    CertificateTrust => ("证书信任", "Certificate trust"),
    CertificateCheckingTitle => ("正在检查服务器证书", "Checking the server certificate"),
    CertificateCheckingHelp => ("正在获取并验证接入点证书，请稍候。", "Retrieving and verifying the gateway certificate. Please wait."),
    CertificateCheckFailed => ("无法检查服务器证书", "Could not check the server certificate"),
    CertificateDecisionFailed => ("无法接受此证书", "Could not accept this certificate"),
    CertificateReviewTitle => ("无法确认服务器身份", "The server identity could not be verified"),
    CertificateReviewWarning => ("服务器证书未通过验证。自签名或私有 CA、证书过期、服务器名称不符都可能导致此提示，也可能意味着服务器被冒充。继续连接可能泄露用户名、密码或其他连接数据。", "The server certificate did not pass verification. A self-signed or private CA certificate, an expired certificate, or a server name mismatch can cause this warning. The server could also be impersonated. Continuing could expose your username, password, or other connection data."),
    CertificateVerifyInstruction => ("请确认接入点正确，并通过可信渠道与管理员核对下面的 SHA-256 指纹。无法确认时，请取消连接。", "Confirm that the gateway is correct and verify the SHA-256 fingerprint below with your administrator through a trusted channel. Cancel if you cannot confirm it."),
    CertificateSessionTrustHelp => ("仅本次连接接受下面这张证书，不保存信任设置。下次连接仍会重新验证。", "Accept only this certificate for this connection. No trust setting is saved; the next connection will verify it again."),
    CertificateRemember => ("记住此证书（保存到当前连接配置）", "Remember this certificate (save to this connection profile)"),
    CertificateRememberHelp => ("不勾选时仅本次信任。勾选后将保存当前连接配置和此 SHA-256 指纹，下次相同指纹无需再次警告；证书更改时仍会拒绝连接，需重新核对并确认。", "Leave unchecked to trust only for this connection. If checked, the current connection profile and this SHA-256 fingerprint will be saved. The same fingerprint will not prompt again; a changed certificate will still be rejected and must be verified and confirmed again."),
    CertificateProfile => ("连接配置", "Connection profile"),
    CertificateEndpoint => ("接入点", "Gateway"),
    CertificateSubject => ("证书主体", "Certificate subject"),
    CertificateIssuer => ("签发者", "Issuer"),
    CertificateNotBefore => ("有效期开始", "Valid from"),
    CertificateNotAfter => ("有效期结束", "Valid until"),
    CertificateFingerprint => ("SHA-256 证书指纹", "SHA-256 certificate fingerprint"),
    CertificateVerificationErrors => ("验证错误", "Verification errors"),
    CertificateNoErrorDetails => ("未提供具体错误信息。", "No specific error details were provided."),
    CertificateCancel => ("取消连接", "Cancel connection"),
    CertificateContinue => ("信任并继续", "Trust and continue"),
    CertificateRememberContinue => ("记住并继续", "Remember and continue"),
    CertificateHelp => ("默认验证系统 CA 与主机名。异常证书可在连接弹窗中确认信任，也可在这里预先填写核实的 SHA-256 指纹。", "System CAs and the hostname are verified by default. Review certificate warnings when connecting, or enter a verified SHA-256 fingerprint here."),
    OvpnCertificateHelp => ("默认使用 .ovpn 配置中的 CA 与服务器身份策略；可额外固定服务器 SHA-256 指纹，切换服务器时请确认该值。", "Uses the CA and server identity policy in .ovpn by default. You may additionally pin the server SHA-256 fingerprint; confirm this value when switching servers."),
    FingerprintHint => ("SHA-256 证书指纹（可选）", "SHA-256 certificate fingerprint (optional)"),
    Routing => ("路由配置", "Routing"),
    RoutePolicy => ("路由模式", "Route policy"),
    RouteGatewayOnly => ("仅网关下发路由（默认）", "Gateway routes only (default)"),
    GatewayRoutesHelp => ("默认仅使用网关实际下发且通过校验的分流路由，不应用手动列表，也不代理所有流量。网关列表为空时不会自动转为全隧道。", "By default, only validated gateway-advertised split routes are used. Manual routes are inactive; this does not enable a full tunnel. An empty gateway list never routes all traffic through the VPN."),
    ManualRoutesInactive => ("当前模式不应用手动路由；选择合并或仅手动模式后可编辑。", "Manual routes are inactive in this mode. Select merge or manual-only mode to edit them."),
    RouteMerge => ("合并网关与手动路由", "Merge gateway and manual routes"),
    RouteManual => ("仅手动路由（覆盖网关）", "Manual routes only (override gateway)"),
    RouteFull => ("全隧道 IPv4", "Full IPv4 tunnel"),
    ManualRoutes => ("手动路由", "Manual routes"),
    ManualRoutesHelp => ("每行一个 IPv4 CIDR；留空表示没有手动路由。仅在合并或仅手动模式下应用，不会改变默认的仅网关下发策略。", "Enter one IPv4 CIDR per line. Empty means no manual routes. Applied only in merge or manual-only mode; gateway-only routing remains the default."),
    RouteSafetyHelp => ("分流模式会拒绝或跳过默认路由及覆盖 VPN 公网网关的路由。修改系统路由需要管理员权限。", "Split modes reject or skip default routes and routes covering the public VPN gateway. Changing system routes requires administrator authorization."),
    FullTunnelHelp => ("只有主动选择全隧道才会接管 IPv4 默认出口，并为 VPN 公网网关保留旁路；更具体的系统路由继续生效，IPv6 不由此模式接管。", "Full tunnel takes over the IPv4 default route only when explicitly selected, preserving a bypass to the public VPN gateway. More specific system routes still apply; IPv6 is not carried."),
    NoManualRoutes => ("未配置手动路由，仅手动模式不会接管业务流量。", "No manual routes are configured; manual-only mode will carry no application traffic."),
    DisconnectToEdit => ("断开连接后可修改配置。", "Disconnect to edit the connection profile."),
    AdvertisedRoutes => ("网关下发路由（只读）", "Gateway-advertised routes (read-only)"),
    AppliedRoutes => ("当前会话生效路由（只读）", "Routes applied this session (read-only)"),
    RoutesAfterConnect => ("连接后显示网关实际下发与本次生效的路由。", "Connect to view the gateway’s actual routes and the routes applied this session."),
    NoAdvertisedRoutes => ("网关未下发 IPv4 路由。", "The gateway advertised no IPv4 routes."),
    NoAppliedRoutes => ("当前会话没有生效的 IPv4 路由。", "No IPv4 routes were applied in this session."),
    SessionEvents => ("会话事件", "Session events"),
    CopyLogs => ("复制日志", "Copy log"),
    LogsHelp => ("连接状态与诊断信息，密码和 OTP 不记录。", "Connection status and diagnostics. Passwords and OTPs are not logged."),
    NoEvents => ("暂无会话事件", "No session events"),
    EventsAfterConnect => ("开始一次连接后，运行状态会显示在这里。", "Connect to see session activity here."),
    OverviewSubtitle => ("你的工作网络，始终触手可及。", "Your work network, always within reach."),
    SettingsSubtitle => ("配置网关、加密方式与路由。", "Configure your gateway, encryption, and routing."),
    LogsSubtitle => ("了解当前连接的每一步。", "Follow each step of your connection."),
    OtpChallenge => ("网关要求输入第二临时密码。", "The gateway requires a temporary second password."),
    OtpTitle => ("第二临时密码验证", "Second-password verification"),
    OtpChallengeHint => ("输入本次验证码 / 第二密码", "Enter your current code / second password"),
    OtpPrivacy => ("第二临时密码 / OTP 仅用于当前登录，始终不会保存。", "Your temporary second password / OTP is used for this login only and is never saved."),
    SubmitOtp => ("提交验证", "Verify"),
    InvalidOtp => ("第二密码必须为 1–31 字节，且不能包含空字符。", "The second password must be 1–31 bytes and contain no null characters."),
    VerifyFailed => ("验证提交失败", "Could not submit verification"),
    Language => ("界面语言", "Language"),
    Theme => ("界面主题", "Theme"),
    ThemeLight => ("浅色", "Light"),
    ThemeDark => ("深色", "Dark"),
    UiPrefsFailed => ("无法保存界面偏好", "Could not save interface preferences"),
    ReadPrefsFailed => ("无法读取界面偏好设置", "Could not read interface preferences"),
    TrayShow => ("显示 SSLRay", "Show SSLRay"),
    TrayHide => ("隐藏窗口", "Hide window"),
    TrayQuit => ("退出 SSLRay", "Quit SSLRay"),
    TrayCreateFailed => ("无法创建系统托盘", "Unable to create system tray"),
    InvalidConfigDirectory => ("应用配置目录无效", "Invalid configuration directory"),
    InvalidGatewayHost => ("网关地址为空或长度超过限制", "Invalid gateway host"),
    GatewayHostnameRequired => ("网关必须是主机名或 IP 地址", "Gateway must be a hostname or IP address"),
    InvalidGatewayPort => ("网关端口无效", "Invalid gateway port"),
    InvalidMtu => ("MTU 必须介于 576 与 1500 之间", "MTU must be 576..1500"),
    InvalidUsername => ("用户名无效", "Invalid username"),
    InvalidFingerprint => ("证书指纹必须是 SHA-256 格式", "Certificate pin must be a SHA-256 fingerprint"),
    InvalidRouteCidr => ("手动路由必须使用 IPv4 CIDR 格式", "Route must use IPv4 CIDR notation"),
    InvalidRouteAddress => ("IPv4 路由地址无效", "Invalid IPv4 route address"),
    InvalidRoutePrefix => ("IPv4 路由前缀无效", "Invalid IPv4 route prefix"),
    InvalidSplitPrefix => ("手动分流路由的前缀长度必须介于 1 与 32 之间", "Manual split-route prefixes must be 1..32"),
    StatusReady => ("准备连接", "Ready to connect"),
    StatusWaitingAdmin => ("等待管理员授权", "Waiting for administrator authorization"),
    StatusReusingAdmin => ("复用本次程序已获的管理员授权", "Reusing administrator authorization"),
    StatusSubmittingOtp => ("正在提交第二临时密码", "Submitting temporary password"),
    StatusRemovingRoutes => ("正在断开连接并清理路由", "Disconnecting and removing split routes"),
    StatusEnterOtp => ("请输入第二临时密码", "Enter the temporary second password"),
    StatusDisconnected => ("连接已断开，已清理路由", "Disconnected; split routes removed"),
    StatusAuthenticatingCisco => ("正在向 Cisco AnyConnect 网关认证", "Authenticating with Cisco AnyConnect gateway"),
    StatusAuthenticatingOpenVpn => ("正在向 OpenVPN 服务端认证", "Authenticating with OpenVPN server"),
    StatusAuthenticating => ("正在向华为 NEM 网关认证", "Authenticating with Huawei NEM gateway"),
    StatusNoRoutes => ("未配置分流路由；可在设置中添加公司网段以承载业务流量", "No split routes configured; add company CIDRs in Settings to carry traffic"),
    StatusConnectedOver => ("已通过以下传输连接", "Connected over"),
    StatusNegotiated => ("协商的传输方式", "Negotiated transport"),
    StatusCreatingRoutes => ("正在创建虚拟网卡，分流路由数量", "Creating virtual interface; split route count"),
    StatusSkippedUnsupported => ("已跳过不支持的网关路由", "Skipped unsupported server route"),
    StatusSkippedGatewayRoute => ("已跳过覆盖公网 VPN 网关的服务器路由", "Skipped server route covering outer VPN gateway"),
}

/// Localize messages emitted by our core/runtime while preserving unknown server
/// diagnostics. The raw source log is retained by the controller.
pub fn diagnostic<'a>(language: Language, message: &'a str) -> Cow<'a, str> {
    let id = match message {
        "Cannot locate the application configuration directory" => {
            Some(Text::ConfigDirectoryUnavailable)
        }
        "Invalid configuration directory" => Some(Text::InvalidConfigDirectory),
        "Profile name is required" => Some(Text::ProfileNameRequired),
        "Profile name must be at most 80 characters" => Some(Text::ProfileNameTooLong),
        "Profile name cannot contain control characters" => Some(Text::InvalidProfileName),
        "A profile with this name already exists" => Some(Text::DuplicateProfileName),
        "Keep at least one connection profile" => Some(Text::LastProfileHelp),
        "Enter the password to save" => Some(Text::PasswordMissingForSave),
        "Saved password must be 1–1024 bytes and contain no null characters" => {
            Some(Text::InvalidSavedPassword)
        }
        "Profile storage is unavailable; repair the profile file before saving" => {
            Some(Text::ProfileStorageBlocked)
        }
        "Prepared OpenVPN configuration cannot be saved" => Some(Text::PreparedOpenVpnNotSavable),
        "Select an OpenVPN .ovpn configuration file" => Some(Text::OvpnPathRequired),
        "OpenVPN does not support the GM TLS mode; select standard cryptography" => {
            Some(Text::OvpnGmUnsupported)
        }
        "Cisco currently supports TLS/CSTP only; select TLS or Auto" => {
            Some(Text::CiscoTransportHelp)
        }
        "Authenticating with Cisco AnyConnect gateway" => Some(Text::StatusAuthenticatingCisco),
        "Authenticating with OpenVPN server" => Some(Text::StatusAuthenticatingOpenVpn),
        "Invalid gateway host" => Some(Text::InvalidGatewayHost),
        "Gateway must be a hostname or IP address" => Some(Text::GatewayHostnameRequired),
        "Invalid gateway port" => Some(Text::InvalidGatewayPort),
        "MTU must be 576..1500" => Some(Text::InvalidMtu),
        "Invalid username" => Some(Text::InvalidUsername),
        "Certificate pin must be a SHA-256 fingerprint" => Some(Text::InvalidFingerprint),
        "Route must be IPv4 CIDR (e.g. 10.0.0.0/8)" => Some(Text::InvalidRouteCidr),
        "Invalid IPv4 route address" => Some(Text::InvalidRouteAddress),
        "Invalid IPv4 route prefix" => Some(Text::InvalidRoutePrefix),
        "Only split routes with prefixes 1..32 are supported" => Some(Text::InvalidSplitPrefix),
        "Ready to connect" => Some(Text::StatusReady),
        "Waiting for administrator authorization" => Some(Text::StatusWaitingAdmin),
        "Reusing administrator authorization" => Some(Text::StatusReusingAdmin),
        "Submitting temporary password" => Some(Text::StatusSubmittingOtp),
        "Disconnecting and removing split routes" => Some(Text::StatusRemovingRoutes),
        "Enter the temporary second password" => Some(Text::StatusEnterOtp),
        "Disconnected; split routes removed" => Some(Text::StatusDisconnected),
        "Authenticating with Huawei NEM gateway" => Some(Text::StatusAuthenticating),
        "No split routes configured; add company CIDRs in Settings to carry traffic" => {
            Some(Text::StatusNoRoutes)
        }
        _ => None,
    };
    if let Some(id) = id {
        return Cow::Borrowed(text(language, id));
    }
    for (prefix, id) in [
        ("Connected over ", Text::StatusConnectedOver),
        ("Negotiated transport: ", Text::StatusNegotiated),
        (
            "Skipped unsupported server route ",
            Text::StatusSkippedUnsupported,
        ),
    ] {
        if let Some(value) = message.strip_prefix(prefix) {
            return Cow::Owned(format!("{}: {value}", text(language, id)));
        }
    }
    if let Some(count) = message
        .strip_prefix("Creating virtual interface with ")
        .and_then(|s| s.strip_suffix(" split routes"))
    {
        return Cow::Owned(format!(
            "{}: {count}",
            text(language, Text::StatusCreatingRoutes)
        ));
    }
    if let Some(route) = message
        .strip_prefix("Skipped server route ")
        .and_then(|s| s.strip_suffix(" covering outer VPN gateway"))
    {
        return Cow::Owned(format!(
            "{}: {route}",
            text(language, Text::StatusSkippedGatewayRoute)
        ));
    }
    Cow::Borrowed(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn language_preferences_have_stable_wire_values() {
        assert_eq!(serde_json::to_string(&Language::ZhCn).unwrap(), "\"zh-CN\"");
        assert_eq!(
            serde_json::from_str::<Language>("\"en\"").unwrap(),
            Language::En
        );
    }
    #[test]
    fn diagnostics_keep_server_details_and_localize_runtime_status() {
        assert_eq!(
            diagnostic(Language::ZhCn, "Negotiated transport: TLS"),
            "协商的传输方式: TLS"
        );
        assert_eq!(
            diagnostic(Language::En, "server error 0x42"),
            "server error 0x42"
        );
        assert_eq!(
            diagnostic(Language::ZhCn, "server error 0x42"),
            "server error 0x42"
        );
    }
}
