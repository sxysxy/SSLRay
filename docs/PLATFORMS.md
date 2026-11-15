# 系统、权限与配置

## 平台依赖

公共要求：Rust 1.95+。各平台包装脚本默认编译项目固定的 OpenSSL 子模块并静态链接；不需要 Homebrew 或系统 OpenSSL 开发库。构建需要 Perl、Python 3.11+ 及对应的原生 C 工具链。

| 系统 | 虚拟网卡 / 路由 | 系统授权 | 额外依赖 |
| --- | --- | --- | --- |
| macOS | 动态编号 `utunN` / `/sbin/route` | 条件优先 Touch ID，系统管理员弹窗备用 | Xcode 命令行工具、Perl、make、Python 3.11+ |
| Linux | `/dev/net/tun` / iproute2 | polkit `pkexec` | iproute2、polkit 及桌面认证代理；GUI 依赖见下方 |
| Windows | Wintun / `netsh store=active` | UAC `RunAs` | MSVC、Windows SDK、原生 Windows Perl、匹配架构的官方 Wintun 0.14.1 `wintun.dll` |

Debian/Ubuntu GUI 构建依赖：

```sh
sudo apt install build-essential pkg-config perl python3 libgtk-3-dev libayatana-appindicator3-dev libxkbcommon-dev
```

Linux 托盘需桌面支持 AppIndicator。Windows 的 `wintun.dll` 使用[官方 Wintun 0.14.1](https://www.wintun.net/builds/wintun-0.14.1.zip) 归档内匹配架构的原始文件，放在可执行文件旁；来源、归档与各架构 DLL 的 SHA-256 见[来源说明](../third_party/wintun/README.md)。helper 从该目录的绝对路径打开 DLL，保持仅共享读取的文件句柄，先核对固定 SHA-256 并通过 `WinVerifyTrust` 验证签名，再用 `LoadLibraryExW` 加载；依赖库搜索限于系统目录。其它版本、内容被修改或签名验证失败时拒绝加载，每次连接创建独立接口。正式分发应保护程序及 DLL 安装目录，附带 Wintun 原始许可证，并完成应用签名和安装包审核。Windows 原生构建及运行验收状态见[验证状态](VALIDATION.md)，固定版本与校验实现不代表各架构已完成实机验证。

## helper 与授权

GUI 以普通权限运行；首次连接启动同一程序的 `--helper` 子进程。macOS/Linux 使用 0700 临时目录内的 Unix socket，发送凭据前核对 root 对端；Windows 使用本机 TCP、随机令牌和内核进程身份检查，双方核对程序与原 GUI PID。凭据不出现在命令行，管理员密码由系统处理。

macOS 仅在系统 sudo PAM 已启用 `pam_tid`、LocalAuthentication 的无弹窗可用性检查通过时优先尝试 Touch ID；不修改 PAM 或授权数据库。仅识别 sudo 或其 sudo_local 中先于其它认证模块的标准 `auth sufficient pam_tid.so` 配置；复杂策略沿用系统密码。实际授权仍受桌面会话、账户及 sudo 策略约束。指纹路径直接执行 `sudo -k -S -p '' -- <helper> ...`，stdin 固定为 `/dev/null`，应用不接收或传递管理员密码；不使用 askpass。带命令的 `-k` 忽略且不更新 sudo 认证缓存，不清空其他会话的 sudo 票据。机制见 [Apple pam_tid](https://github.com/apple-oss-distributions/pam_modules/blob/main/modules/pam_tid/pam_tid.c) 和 [sudo 手册](https://github.com/sudo-project/sudo/blob/main/docs/sudo.man.in)。

指纹不可用时使用原系统管理员弹窗；一旦开始指纹尝试，取消、失败或超时均不会自动再弹密码框。用户可通过显式按钮重试或选择系统密码授权；helper 已启动后的握手、通信或会话错误也不会自动触发第二次提权。下述 helper 复用期限不因授权方式改变。真实生物识别及系统密码提权仍待实测，见[验证状态](VALIDATION.md)。

监听端非阻塞，已接入通道显式恢复阻塞并设置读取时间片；握手按总期限等待分片，可响应取消。这样避免 macOS 将暂时没有握手数据的 `EAGAIN` 误报为授权失败；对端身份、nonce 和就绪探测均通过后才发送 VPN 凭据。

helper 同次运行可复用，空闲 10 分钟退出，授权满 1 小时后不再接受新会话；活动隧道不受该期限影响。每次断开清理本次接口和路由；退出应用或 IPC 断开会取消会话并关闭 helper。授权取消、失败或超时提供显式重试，不自动重试网关登录。

## 路由策略

| `route_mode` | 采用的业务路由 |
| --- | --- |
| `gateway_only`（默认） | 网关下发且通过校验的 IPv4 分流网段；不应用手动列表 |
| `merge` | 有效网关路由与手动网段去重合并 |
| `manual_only` | 仅手动网段，覆盖网关策略；列表为空则不安装业务路由 |
| `full_tunnel` | 保护所有实际外层对端后安装两条 `/1`；不应用手动列表 |

默认跳过网关的 `/0` 和两条 `/1` 覆盖路由；OpenVPN `redirect-gateway` 也不会自行启用全隧道。`routes: []` 表示无手动路由，无效或空下发不会被替换为猜测网段。下发路由覆盖外层对端时跳过，手动路由覆盖对端时报错。

全隧道先查询每个实际连接对端的原出口，必要时添加自有 `/32` 旁路，再安装 `0.0.0.0/1`、`128.0.0.0/1`。已有更具体路由仍生效；原出口有歧义、已指向本次 VPN 接口，或 Linux 使用非 main 策略表时终止连接。它不阻断 IPv6、不隔离局域网，也不是 kill switch。

标准加密下，旧版华为网关的 CHIV3 UDP 自动探测、协商和验证。Auto 遇到不支持或传输不可用时在同一已认证控制连接切回 TLS，不重新提交口令；显式 UDP 模式则报告失败。旧 `allow_legacy_udp` 字段仅为兼容已有 JSON 保留，不再控制协商。国密始终使用 TLS；加载旧版 GM+UDP GUI 配置时保留 GM、将传输修正为 TLS，保存前不改原文件。

core 中的 `RouteGuard` 仅以 `add` 安装路由，不清空或替换系统路由。冲突时逆序回滚本次新增项，既有路由不归 SSLRay 清理。界面分别显示下发和实际安装列表；清理失败保留安装列表供排错。具体事务实现见 [platform.rs](../crates/sslray-core/src/platform.rs)，实机边界见[验证状态](VALIDATION.md)。

## 本地配置与凭据

配置目录由 `ProjectDirs` 决定，保存主密码的确认框会显示本机完整路径：

| 系统 | 默认配置目录 |
| --- | --- |
| macOS | `~/Library/Application Support/tech.SSLRay.SSLRay/` |
| Windows | `%APPDATA%\SSLRay\SSLRay\config\` |
| Linux | `$XDG_CONFIG_HOME/sslray/`，未设置时为 `~/.config/sslray/` |

源码目录、程序所在目录和管理员 helper 的身份不会改变这些用户配置路径；CLI 配置文件则由 `--profile` 明确指定。

- `profiles.json`：多 Profile、稳定 ID、上次选择及可选的 `saved_password_base64`。Base64 可直接还原，不是加密；Unix 文件权限为 0600，Windows 依赖用户目录权限。取消保存并保存配置后移除主密码，复制 Profile 不复制密码；OTP 永不保存。旧版多配置的 `saved_password` 明文字段在下次保存时改为 Base64。
- `ui-preferences.json`：语言 `zh-CN` / `en`、主题 `light` / `dark`，不含凭据。
- 旧 `profile.json`：首次迁移为多配置并保留原文件。读取失败不覆盖原文件；CLI 仍使用单 Profile JSON。

旧配置 `use_server_routes: false` 在缺省、`gateway_only` 或 `merge` 策略下按 `manual_only` 处理。手动值仅在 `merge` / `manual_only` 下校验、应用。

华为/Cisco 在申请管理员权限、发送凭据前进行仅含 TLS 的证书预检。自签名、私有 CA、过期或名称不匹配时可查看主体、签发者、有效期和 SHA-256，明确确认后继续。未勾选记住时，仅对本次连接副本固定该证书；勾选后保存当前 Profile 及 `certificate_sha256`，不额外启用密码保存，OTP 仍不保存。证书变化会拒绝连接，修改网关、端口、协议或加密模式会清空旧指纹；异步报告与确认均绑定当前 Profile/端点。坏签名、撤销或算法错误不提供继续选项。OpenVPN 仍遵循其配置中的 CA 与身份策略。

静态 OpenSSL 不依赖构建机的证书路径：Linux 优先尊重显式 `SSL_CERT_FILE` / `SSL_CERT_DIR`，否则查找发行版标准 CA bundle；Windows 只读导入系统 ROOT，并过滤用途限制与 Disallowed。后者不是完整 Schannel 链策略或在线吊销实现。显式证书指纹保持独立，不会把一次确认写入系统信任库。

主密码/OTP/会话密钥使用 `zeroize` 尽力清理，无法保证系统换页和库内部缓冲全部擦除。保存到本地的内容不上传云端，但需保护文件和备份。软件设置仅按本次会话的精确接口名查询，不显示其他适配器；未连接时不查询，最终断开确认后清空。Unix 使用 `getifaddrs` 和 MTU 查询，Windows 使用固定 PowerShell/.NET 查询（5 秒、1 MiB 上限）；异步结果校验会话代数，防止同名重连显示旧数据。查询失败仅显示本会话已知信息，并区分配置 MTU 与实测值。

## 发行包目录

版本、平台和架构保留在外层发行文件名中。Windows ZIP、Linux tar.gz 和完整源码 tar.gz 解压后均为单一 `SSLRay/` 根目录；Windows 入口是 `SSLRay/SSLRay.exe`，Linux 入口是 `SSLRay/SSLRay`，源码构建命令在展开后的 `SSLRay/` 内执行。源码包包含固定 OpenSSL 及锁定的 Cargo vendor 依赖和离线配置，Rust 工具链、系统 SDK 与原生构建工具另行准备。

macOS 发布文件为 `SSLRay-<版本>-macos-<架构>.dmg`，卷名为 `SSLRay`，可见内容为 `SSLRay.app` 和指向 `/Applications` 的 `Applications` 快捷方式。打开映像后可将应用拖入“应用程序”。目录和容器命名不改变应用的签名、公证或运行验收状态。

## macOS 构建与打包

初始化官方 [OpenSSL 子模块](../third_party/openssl)后，用 [cargo-macos.sh](../scripts/cargo-macos.sh) 运行 Cargo；[bundle-macos.sh](../scripts/bundle-macos.sh)共享相同配置。构建固定源码版本的静态库，缓存于 `work/`，不在子模块内生成构建文件，不使用 Homebrew OpenSSL。源版本和许可证见[第三方说明](THIRD-PARTY.md)。

`bundle-macos.sh [输出目录]` 默认生成 `dist/SSLRay.app` 与 `dist/SSLRay-<版本>-macos-<架构>.dmg`。独立入口 `package-dmg-macos.sh APP_PATH OUTPUT_DMG` 可将已有已签名应用打入映像，不重新编译或修改应用文件；映像以只读方式挂载，核对应用文件及 `Applications -> /Applications` 结构。

默认 `MACOSX_DEPLOYMENT_TARGET=11.0`，主程序及 TLS 库均按同一目标编译、检查 Mach-O 要求；打包拒绝非系统动态依赖，`Info.plist` 仍从实际二进制计算下限。`SSLRAY_MACOS_ARCH` 可选择 `arm64` 或 `x86_64`（需对应 Rust target）；当前仅构建验证 Apple Silicon，旧系统和 Intel 运行仍待实测。[Rust 平台要求](https://doc.rust-lang.org/rustc/platform-support/apple-darwin.html)允许 arm64 以 11.0 为目标。

需要 Python 3.11+，客户端运行不需要 Python。高级构建可用 `OPENSSL_DIR` 指定满足同一部署目标的静态后端，并以 `SSLRAY_TLS_SOURCE_DIR` 指定其实际源码以收集许可；缺失或不匹配会报错。两种平台图标来自同一 [SVG](../assets/sslray.svg)：Windows 嵌入 ICO，macOS 包内使用 ICNS。Linux/Windows、全隧道及异常退出的验收边界见[验证状态](VALIDATION.md)。
