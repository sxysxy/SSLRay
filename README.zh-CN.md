# SSLRay

[English](README.md) | **简体中文**

Rust 实现的 SSL VPN 桌面客户端，使用 egui 界面，支持多 Profile、系统托盘、后台运行、中英文和浅色/深色主题。当前为开发版本，主要验证环境是 macOS Apple Silicon；Linux、Windows 已有平台实现，尚待实机验证。

| 协议 | 实现范围 | 已验证环境 |
| --- | --- | --- |
| 华为 SecoClient / UniVPN NEM | TLS、实验性 UDP、已识别的第二密码挑战 | 真实网关设备 TLS/旧版 UDP 的 IP 往返及 utun SSH |
| Cisco AnyConnect | XML 认证、TLS/CSTP；暂不支持 DTLS | 本地 ocserv，未验证 Cisco 硬件 |
| OpenVPN | 原生 Rust 引擎、证书/密码认证、TCP/UDP | 本地 OpenVPN 2.6.20，UDP / AES-256-GCM |

当前只承载 IPv4，不自动修改系统 DNS，无 kill switch 或自动重连。国密支持 RFC 8998 TLS 1.3（SM2/SM3/SM4），需要后端和网关共同支持，OpenVPN 暂不支持；TLCP 双证书、USBKey 未实现。详细结果见[验证状态](docs/VALIDATION.md)。

## 编译与启动

需要 Rust 1.95+、兼容的 OpenSSL 开发库及[平台依赖](docs/PLATFORMS.md)。

```sh
cargo run -p sslray
```

macOS 开发包另需 Python 3.11+：

```sh
./scripts/bundle-macos.sh
open dist/SSLRay.app
```

脚本捆绑 TLS 动态库、收集许可证并做 ad-hoc 签名。当前 Apple Silicon 开发包要求 macOS 26.0+；实际下限由本次二进制和所带库决定。

## 使用

1. 在“连接设置”中新建 Profile，填写唯一名称。华为/Cisco 填网关和账号；OpenVPN 可用“选择文件…”导入 `.ovpn` 路径。
2. 默认校验证书；私有 CA 网关可填写经管理员核实的 SHA-256 指纹。OpenVPN 遵循配置中的 CA/服务器身份策略。
3. 默认仅使用网关下发的有效分流路由，手动列表为空。全隧道必须主动选择；下发与实际应用路由分别只读显示。
4. 保存 Profile，在概览中按名称选择并连接。缺少主密码时会临时询问；OTP 可预填或按网关挑战输入。
5. 首次连接申请管理员权限，同次运行可复用 helper。空闲 10 分钟或授权满 1 小时后的新连接重新申请，活动隧道不中断；授权失败可手动重试。

Profile 可复制、重命名和删除，切换前会提示处理未保存修改。“软件设置”提供外观、语言、适配器和版本信息；有托盘时关闭窗口会隐藏，退出应用才结束会话。

主密码默认不保存。启用“保存主密码到本地”后以 **Base64** 写入本机 `profiles.json`，确认框显示完整路径；Base64 可还原，并非加密，不上传云端。**OTP 始终不保存**。配置迁移、权限及路由策略见[系统与配置说明](docs/PLATFORMS.md)。

华为旧版 CHIV3 UDP 需显式启用，使用 AES-128-CBC 且无逐包 MAC；Auto 默认对此类网关保持 TLS。国密模式不回退普通算法，也不使用 AES UDP 数据面。

## 命令行

```sh
cargo run -p sslray -- capabilities
cargo run -p sslray -- inspect --host vpn.example.com --port 443
cargo run -p sslray -- example --output profile.json
cargo run -p sslray -- auth-test --profile profile.json
cargo run -p sslray -- connect --profile profile.json
```

`auth-test` 不修改宿主网卡或路由；`connect` 前台运行，Ctrl-C 断开清理。CLI 使用单 Profile JSON；密码由隐藏提示输入，自动化可用 `--password-stdin`，第二密码用 `--otp`。不要把凭据放入命令参数、环境变量或版本库。

## 开发与文档

`sslray-core` 是协议、加密、网卡与路由库；`sslray-app` 提供 GUI/CLI，并通过已认证 IPC 管理同一可执行文件的特权 helper 子进程。helper 调用 core 运行隧道，UI 保持普通权限。

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

- [系统、权限与路由](docs/PLATFORMS.md)
- [华为 NEM](docs/HWNEM.md) · [Cisco](docs/CISCO.md) · [OpenVPN](docs/OPENVPN.md)
- [国密后端](docs/GM-VALIDATION.md)
- [验证状态与复验](docs/VALIDATION.md)
- [第三方来源与许可](docs/THIRD-PARTY.md)
