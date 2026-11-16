# 验证记录

## 0.2.0：托盘状态同步

更新：2026-11-16。未连接时保留原蓝色，已连接为绿色，连接中、等待第二密码及断开中为黄色，失败为红色。后台轮询后同步托盘，菜单的“断开”仅在已连接时启用；迟到的菜单点击、握手成功或第二密码事件不能让已失败或取消的会话恢复为已连接。提示文字随界面语言变化；Linux 的托盘库不支持悬浮提示，使用只读状态菜单项补充。

三平台均完成全工作区、全部 targets 的离线测试和严格 Clippy `-D warnings`，统一源码格式检查通过；4 项需要外部参考服务的互通测试继续忽略。新增 10 项回归覆盖隐藏窗口时正常/异常断开、清理期间及之后的迟到点击、取消后的迟到握手/OTP、重新连接、状态颜色、本地化、图标透明边缘与白色闪电、GTK 最新完整状态投递和失败重试节流。自动测试不创建真实托盘。

| 平台 | 本轮构建与回归 | 包与运行检查 | 边界 |
| --- | --- | --- | --- |
| macOS arm64 | **184 通过、4 忽略**；release、fmt、严格 Clippy 通过 | `.app` / DMG、CLI 0.2.0、静态 OpenSSL 4.0.3 / 国密能力；只读挂载验证 `SSLRay.app` 和 `Applications -> /Applications`，440 文件、含根目录的 713 项及权限一致，严格签名检查通过并已卸载 | 目标 macOS 11.0；ad-hoc 签名，未公证；未在旧系统或 Intel 实机运行 |
| Linux x86_64 | **174 通过、4 忽略**；manylinux 2.28 / GTK 3.22.30 / Rust 1.96，release、严格 Clippy 通过 | 包内 launcher 的版本与国密能力检查通过；仅 `SSLRay/` 根目录、503 文件及 502 项内部哈希清单通过，launcher 和私有 ELF 权限 0755；最高 GLIBC 2.28，无动态 libssl/libcrypto 或 RPATH，259 项第三方许可无缺项 | 使用独立源码/缓存与隔离容器；未启动桌面 GUI、触发 polkit 或建立实际 TUN/VPN |
| Windows x64 | **168 通过、4 忽略**；经 Windows App 远程桌面原生 MSVC release、fmt、严格 Clippy 通过 | CLI 0.2.0 / 国密能力；静态 CRT/OpenSSL；原版 Wintun 0.14.1 的哈希、许可和 Authenticode Valid；原生包解压验证，界面启动、蓝色未连接托盘、“断开连接”禁用及托盘退出成功，测试进程已结束 | SSLRay.exe 未签名；本轮未触发 UAC、创建网卡/路由或登录真实网关。交付 ZIP 仅规范化路径分隔符，文件内容与本轮原生包一致；规范化容器未在 Windows 上再次解压 |

三个包的内层名称保持 `SSLRay`；macOS 使用 `SSLRay.app`，Windows 使用 `SSLRay/SSLRay.exe`，Linux 使用 `SSLRay/SSLRay` launcher 与 `bin/SSLRay`。完整 GPL 对应源码另含固定 OpenSSL 源码和 489 项离线 Cargo 依赖。Windows 源码隔离构建未改原项目，临时传输监听已停止；0.1.0 正式产物保持独立。

本轮未重跑实际 VPN 数据互通、全隧道或锁屏整夜试验；下方 0.1.0 的运行验收均为历史记录，不构成 0.2.0 的连接实测。`gm_tls13=true` 只表示本地能力，不代表实际国密网关握手成功。

## 0.1.0：历史验证记录

更新：2026-11-15。三平台最终代码已完成构建、回归及下述范围的运行检查。下表区分受控 OpenVPN 参考服务、此前真实网关实测及尚未通过的企业接入，不将本轮结果扩展到未测试的系统、硬件或协议组合。

### 本轮平台检查

| 平台 | 构建与回归 | 已验证运行范围 | 边界 |
| --- | --- | --- | --- |
| macOS arm64 | **174 通过、4 忽略**；fmt、全 targets Clippy `-D warnings` 通过 | `.app`、CLI 0.1.0、统一图标、静态 OpenSSL 4.0.3、国密能力检查；DMG 只读挂载后应用 440 文件、含根目录的 713 项及权限一致，严格签名校验通过 | 目标 macOS 11.0，未在旧系统或 Intel 实机运行；ad-hoc 签名，未公证，Gatekeeper 不接受其为已认证分发 |
| Linux x86_64 | **164 通过、4 忽略**；全 targets Clippy `-D warnings` 通过，最终 UI 的 73 项 app 测试与严格 Clippy 再次通过 | manylinux 2.28 构建、Ubuntu 原生启动；最终 CLI 经显式 sudo 建立宿主 TUN、仅测试目标 `/32`，OpenVPN 参考服务 ping 2/2 及清理通过；另有隔离命名空间 TUN 测试 | ELF 最高要求 GLIBC 2.28；此前 Xvfb 界面截图未在最后日志布局修正后重拍；桌面托盘及 polkit 人工交互未验收，企业网关数据仍未通过 |
| Windows x64 | **158 通过、4 忽略**；全 targets Clippy `-D warnings`、原生 release、静态 CRT/OpenSSL、官方 Wintun 0.14.1 哈希与 Authenticode 检查通过 | 真实 UAC、官方 Wintun、VIP/MTU、受限 `/32`、OpenVPN 参考服务 ICMP、断开清理及同一管理员 helper 重连复用通过；日志列表可见，深色英文检查后恢复中文浅色并退出 | 本次主机及证书认证/UDP 组合的实测，不代表其他 Windows 版本、硬件、全部 OpenVPN 选项或企业华为网关已通过 |

三端平台包装脚本使用固定的项目 OpenSSL 源码，运行不需要系统 OpenSSL。macOS 动态导入仅含 Apple 系统库；Linux 无动态 `libssl` / `libcrypto` 和绝对 RPATH。Windows 已修复读超时使 OpenSSL 会话永久失效的问题，回归覆盖连续超时后恢复收包、分片及 EOF；仅看到 `gm_tls13=true` 仍不代表实际国密网关握手通过。

应用与核心的非测试代码禁止直接 `unwrap` / `expect`。回归覆盖证书预检与指纹、OTP、Base64 凭据隔离、Profile、路由事务、helper 复用、i18n、布局和错误摘要。短负认证响应保留网关状态码，不再误报为系统读取超时；完整短信挑战与不自动重复登录的策略不变。新增 3 项 OpenVPN 回归覆盖忽略完整 IPv6 数据后继续 IPv4 会话、有限读取预算，以及继续拒绝损坏的 IPv4/IPv6 和非 IP 数据；这不提供 IPv6 接入或路由。

### 发行布局

外层文件名保留版本、平台与架构。Windows ZIP、Linux tar.gz 和完整源码 tar.gz 的解压根目录统一为 `SSLRay/`。macOS 使用 DMG，卷名 `SSLRay`，根部可见 `SSLRay.app` 及指向 `/Applications` 的快捷方式；本地开发仍可直接启动 `.app`。实际只读挂载确认这两个可见项及链接目标正确，应用内容与目录权限保持原样，`codesign --verify --deep --strict` 通过，并确认映像已卸载。新独立输出目录和将已有已签名应用单独打入 DMG 的入口均通过；拒绝向应用包内部写入输出的检查也已实测，源应用未改变。容器调整未重跑或扩大上述运行测试范围；重新打包的文件与容器校验见发行文件旁的独立记录。

### 网络与授权范围

| 场景 | 已验证结果 | 尚未覆盖 |
| --- | --- | --- |
| 真实网关设备：macOS 此前实测 | 华为 TLS/旧版 UDP 的匹配 IP 回复；分别通过 SSLRay utun、单目标 `/32` 完成公钥 SSH，断开清理 | 本轮未再次登录；全部下发路由、合并及全隧道未完成实机验收 |
| 真实网关设备：Linux 本轮 | 仅 TLS 的预检取得批准的叶证书指纹；一次认证收到负状态 `-5`，未创建 VIP、网卡或路由；宿主 SSH、默认路由及接口与基线一致 | 认证未成功，未重试、未测 UDP，不宣称实际 VPN 数据通过 |
| 真实网关设备：Windows 本轮 | 企业华为网关证书预检及警告信息；当前测试账号认证未获成功 | 企业华为 TLS/UDP 数据通路仍待验收；下述成功的 Windows OpenVPN 参考测试不替代这一结果 |
| Linux 隔离 TUN 本轮 | 隐藏 sudo 进入新网络命名空间，现有 core 创建 TUN/MTU 1400，唯一 `198.18.0.2/32`；真实 ICMP 2/2、TX/RX 各 168 字节，显式清理后恢复命名空间基线 | 不使用企业账号、不访问真实网关、不修改宿主业务路由；不能替代 VPN 互通测试 |
| OpenVPN：macOS 此前实测 | 本地 OpenVPN 2.6.20 UDP / AES-256-GCM、证书认证、IP 往返、错误指纹拒绝；经 macOS utun 系统 ping 2/2 与清理 | 其他 TCP/MFA/算法组合仍待验收 |
| OpenVPN：Linux 本轮参考服务 | 最终原生 CLI 对临时 OpenVPN 2.7.0 参考服务，双向证书认证、UDP / AES-256-GCM；宿主 `tun0`、VIP `10.88.0.2`、MTU 1400，仅 `10.88.0.1/32`；ping 2/2、TX/RX 各 168 字节，SIGINT 后退出 0，路由与接口恢复基线 | 使用显式 sudo CLI，不等同于桌面 polkit；未使用企业账号，不证明华为网关或其他协议组合互通 |
| OpenVPN：Windows 本轮参考服务 | 最终 GUI 经真实 UAC 加载官方 Wintun 0.14.1，VIP `10.88.0.2/32`、MTU 1400，仅手动 `10.88.0.1/32`；首次会话 ping 2+6 共 8/8，断开后同一 helper 无新 UAC 重连，另 2/2；两次断开均清理接口/测试路由 | 仅证书认证、UDP / AES-256-GCM 对临时 OpenVPN 2.7.0 服务；未安装 SSLRay 默认路由，外层连接及原默认路由不变，不代表全隧道或企业网关通过 |
| Cisco 此前实测 | 本地 ocserv 1.6.0 / GnuTLS 3.8.13：密码认证、TLS/CSTP、IP/DNS 往返与错误指纹拒绝 | Cisco 硬件、DTLS、宿主网络完整组合未验证 |
| 国密与 OTP | 本地 RFC 8998 SM4-GCM/CCM 握手及应用数据、算法向量与模拟挑战通过 | 真实设备的国密、OTP、TLCP 双证书和 USBKey 未验证 |

macOS 指纹授权按 PAM/LocalAuthentication 可用性选择，决策与失败状态有自动测试；本轮没有触发真实 Touch ID 或系统密码认证。Linux 的隔离 sudo 和宿主 OpenVPN sudo CLI 测试均不代表桌面 polkit 已验收。helper 的 10 分钟空闲与 1 小时授权期限由自动测试覆盖；Windows 本轮首次连接完成真实 UAC，断开重连复用同一 helper，并实际记录“Reusing administrator authorization”，没有第二次 UAC。

Windows 本轮人工确认日志列表的 4 行事件可见；英文深色检查后恢复中文浅色，接受退出。Linux 最终原生包的日志修正通过测试与 Clippy，未借用 Windows 截图宣称 Linux 最终界面已重拍。参考服务、监听端口、临时配置均已清理；受控服务端收到 Windows 10 组及 Linux 2 组 ICMP 请求/回复，过滤后的报文及基线材料保存在发行目录的 `reference-openvpn-validation/`，Windows 客户端证据另在 `windows-validation/`。两类材料分别验证数据到达与客户端清理，不互相替代。

### 复验

在仓库根目录使用对应平台的 Cargo 包装脚本，详见 [平台说明](PLATFORMS.md)、[Linux 构建](LINUX-BUILD.md)及 [Windows 构建](WINDOWS-BUILD.md)：

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo run -p sslray -- capabilities
cargo test -p sslray-core --test gm_tls -- --nocapture
```

普通测试只访问本地模拟服务。4 项容器互通测试默认忽略；准备好服务后可分别运行 `openvpn_interop`、`cisco_interop`，使用 `--ignored --test-threads=1`，见 [OpenVPN](OPENVPN.md)、[Cisco](CISCO.md)。

真实设备的纯 IP 探测使用 `sslray-core` 的 `probe_data` 示例；宿主测试用 CLI `connect`，凭据仅通过隐藏输入或显式 stdin 提供。先核对证书、保护外层连接并限制测试路由，断开后复核基线。实验材料保存在忽略的 `work/`；文档、版本库和发行包不包含本次企业接入的真实密码、OTP、令牌、私钥或原始认证报文。完整源码归档保留上游公开的测试样例与测试密钥，它们不属于本次企业接入凭据。
