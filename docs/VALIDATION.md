# 验证状态

最近测试：2026-11-15，macOS 27.2.1 / Apple Silicon。最近验证证书预检、确认信任及按 Profile 记住指纹；真实网关设备仅做不发送凭据的证书预检，未重新登录或修改系统网络。

## 自动检查

| 项目 | 最近记录 | 范围 |
| --- | --- | --- |
| 工作区回归 | **126 通过、0 失败、4 忽略** | 项目静态 OpenSSL；协议、路由、证书、OTP、i18n、配置/凭据、helper 与会话适配器 |
| 证书预检与选择 | 8 项本地 TLS + 12 项应用状态检查通过 | 自签名/过期/名称不符、正常 CA、坏签名硬失败、错误/变化 pin、预检无应用数据、目标绑定与迟到结果、仅本次及记住后重载、未授权密码/OTP 不落盘 |
| 项目 OpenSSL 4.0.3 | **9 通过、0 跳过** | 独立静态后端：TLS/证书 pin、第二密码、原生记录边界及 RFC 8998 两种 SM4 套件的应用数据往返 |
| 参考服务互通 | 前次网络联调 **4 项通过** | OpenVPN 与 ocserv 各 2 项；最近回归未启动容器，未计入 99 项 |
| 独立 OpenVPN 引擎 | 前次 **18 项通过** | PRF、控制/数据通道、重放、密钥更新、OTP 不复用和算法策略；不计入工作区 |
| 格式 / Clippy / 开发包 | 通过 | fmt、`clippy -D warnings`、release 构建、`codesign --verify --deep --strict` |
| 源码 / 图标 | 通过 | OpenSSL 完整 tree 校验及 8 项导出/篡改反例；统一 PNG/ICO/ICNS 内容、尺寸和 macOS 图标解码 |

新 macOS 包为 arm64，主程序及全部 1,124 个 TLS 静态库 Mach-O 成员的最低目标均为 11.0，`Info.plist` 与主程序一致。动态导入仅含 Apple 系统库，无 Homebrew 或 TLS 动态库；运行时报告 OpenSSL 4.0.3、`gm_tls13=true`。未在 macOS 11 或 Intel 上运行验证。Windows ICO 已接入可执行文件资源，尚未在 Windows 构建或检查外观。

## 网络实测

| 场景 | 已验证结果 | 边界 |
| --- | --- | --- |
| 真实网关设备（华为）TLS | 原生认证、8 条下发路由、匹配的 DNS 与 ICMP 回复 | 纯 IP 探测不修改宿主接口、路由或 DNS |
| 真实网关设备（华为）旧版 UDP | 显式 CHIV3 / AES-128-CBC，收到同目标的匹配 ICMP 回复 | 无逐包 MAC，需主动启用；Auto 保持 TLS |
| 真实网关设备 TLS / UDP 宿主 SSH | 各经 SSLRay utun 和单目标 `/32`，公钥 SSH 静态命令退出 0；Ctrl-C 后自有接口和路由清理 | 禁用 SSH 代理/复用并严格检查 host key；未安装真实网关设备的全部路由 |
| OpenVPN 2.6.20 | UDP / AES-256-GCM 证书认证、纯 IP ICMP 往返及错误指纹拒绝；默认 `gateway_only` 经 utun 系统 ping **2/2**，断开清理 | 本地 Docker 参考服务；不代表 TCP/MFA 等其他组合均通过 |
| ocserv 1.6.0 / GnuTLS 3.8.13 | 密码认证、TLS/CSTP、纯 IP ICMP/DNS 往返及错误指纹拒绝 | 本地参考服务；未测 Cisco 硬件或该协议的宿主路由 |
| 国密 / OTP | 本地 RFC 8998 握手及应用数据、算法向量、模拟挑战通过 | 未验证真实网关设备的国密或 OTP；详见[国密记录](GM-VALIDATION.md) |
| 真实网关设备证书预检 | TLS 1.2 / ECDHE-RSA-AES256-GCM-SHA384；报告自签名链及主机名不符，取得指纹及有效期 | 不发送用户名、密码、HTTP/NEM 数据，不代表本次已完成 VPN 登录；过期场景由本地证书测试覆盖 |

真实网关设备默认下发的八条分流路由的完整系统复验尚未完成验收：最后一次因 macOS 授权等待超时未进入安装阶段。另一个活动 VPN 可重装相同网段路由、改变实际出口，联调应避免并发 VPN 干扰。

## GUI、配置与授权

- 已人工检查：按名称选择/新建 Profile、重启恢复选择、软件设置、浅色/深色、中英文、适配器/IP/MTU、版本、分流路由列表及空手动列表、菜单 Quit。
- 本次已打开新包检查软件设置：未连接时仅提示连接后显示 SSLRay 网卡，不列出系统其他接口；后端显示 OpenSSL 4.0.3。连接后的精确接口匹配、断开清空及同名重连旧结果隔离通过自动测试，未再次连接网关人工检查。
- 原生文件框已成功选择 `.ovpn` 并回填路径；密码保存确认框已检查本地路径、云端与泄露提示。
- 已人工检查接入配置、网卡刷新、日志及 MTU 标题行的居中对齐；主密码框内的眼睛按钮可切换掩码/明文，本地保存选项紧邻下方。临时密码弹窗使用同一控件，取消后清空并恢复隐藏；该检查未提交登录或申请管理员权限。
- Base64 存储测试覆盖旧明文升级、严格解码、边界与冲突拒绝、0600、配置损坏保护及密码隔离。
- helper 复用、10 分钟空闲/1 小时授权期限、父进程断开、重叠会话拒绝、授权失败分类和显式重试通过 IPC/状态测试；新复用实现未再次实测系统弹窗次数。
- 已在非特权本机复现 macOS 接入流继承 `O_NONBLOCK`，导致授权后读握手立即返回 `EAGAIN / os error 35`；仅设置读取超时无效。现对已接入流恢复阻塞，监听端仍非阻塞；nonce/Ready 按总期限等待并保留分片，取消后不发送 Connect。另覆盖对端关闭后仍有缓存数据的读取。本次未触发真实管理员授权、创建网卡或修改路由，完整授权流程仍需使用新包实测。

尚待验收：Linux/Windows 运行时、Cisco 宿主网络、真实网关设备全部下发路由/合并策略、IPv4 全隧道、真实 OTP、更多认证组合、长期稳定性，以及崩溃/强退/活跃 GUI 退出等完整清理场景。托盘 Restore 与真实 OTP 弹窗也未完成人工验收。

## 复验入口

在仓库根目录执行；普通测试不连接真实网关设备。macOS 将下列 `cargo` 替换为 `./scripts/cargo-macos.sh`，以使用项目后端：

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo run -p sslray -- capabilities
cargo test -p sslray-core --test gm_tls -- --nocapture
```

`gm_tls` 在后端不支持时会输出跳过原因；仅看到 `ok` 不能证明国密握手成功。服务准备好后再执行实际互通测试：

```sh
cargo test -p sslray-core --test openvpn_interop --locked -- --ignored --test-threads=1
cargo test -p sslray-core --test cisco_interop --locked -- --ignored --test-threads=1
```

容器准备及停止方法见 [OpenVPN](OPENVPN.md)、[Cisco](CISCO.md)；实验材料保存在忽略的 `work/`，不作为应用产物。真实网关设备的纯 IP 探测入口为 `sslray-core` 的 `probe_data` 示例；宿主联调用 CLI `connect`，凭据仅通过隐藏输入或显式 stdin 提供。文档、日志和版本库均不应包含密码、OTP、令牌、私钥或未脱敏抓包。
