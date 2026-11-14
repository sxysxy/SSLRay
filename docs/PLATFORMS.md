# 系统、权限与配置

## 平台依赖

公共要求：Rust 1.95+、兼容的 OpenSSL 开发库。

| 系统 | 虚拟网卡 / 路由 | 系统授权 | 额外依赖 |
| --- | --- | --- | --- |
| macOS | 动态编号 `utunN` / `/sbin/route` | 管理员授权弹窗 | 如 `brew install openssl@3` |
| Linux | `/dev/net/tun` / iproute2 | polkit `pkexec` | iproute2、polkit 及桌面认证代理；GUI 依赖见下方 |
| Windows | Wintun / `netsh store=active` | UAC `RunAs` | MSVC、OpenSSL（如 vcpkg）、匹配架构的签名 `wintun.dll` |

Debian/Ubuntu GUI 构建依赖：

```sh
sudo apt install build-essential pkg-config libssl-dev libgtk-3-dev libayatana-appindicator3-dev libxkbcommon-dev
```

Linux 托盘需桌面支持 AppIndicator。Windows 的 `wintun.dll` 从[官方](https://www.wintun.net/)获取并放在可执行文件旁；helper 只从该目录加载并核验签名，每次创建独立接口。正式分发应保护程序及 DLL 安装目录，并完成相应签名、公证和安装包审核。

## helper 与授权

GUI 以普通权限运行；首次连接启动同一程序的 `--helper` 子进程。macOS/Linux 使用 0700 临时目录内的 Unix socket，发送凭据前核对 root 对端；Windows 使用本机 TCP、随机令牌和内核进程身份检查，双方核对程序与原 GUI PID。凭据不出现在命令行，管理员密码由系统处理。

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

core 中的 `RouteGuard` 仅以 `add` 安装路由，不清空或替换系统路由。冲突时逆序回滚本次新增项，既有路由不归 SSLRay 清理。界面分别显示下发和实际安装列表；清理失败保留安装列表供排错。具体事务实现见 [platform.rs](../crates/sslray-core/src/platform.rs)，实机边界见[验证状态](VALIDATION.md)。

## 本地配置与凭据

配置目录由 `ProjectDirs` 决定；macOS 为 `~/Library/Application Support/tech.SSLRay.SSLRay/`。保存主密码的确认框会显示本机完整路径。

- `profiles.json`：多 Profile、稳定 ID、上次选择及可选的 `saved_password_base64`。Base64 可直接还原，不是加密；Unix 文件权限为 0600，Windows 依赖用户目录权限。取消保存并保存配置后移除主密码，复制 Profile 不复制密码；OTP 永不保存。旧版多配置的 `saved_password` 明文字段在下次保存时改为 Base64。
- `ui-preferences.json`：语言 `zh-CN` / `en`、主题 `light` / `dark`，不含凭据。
- 旧 `profile.json`：首次迁移为多配置并保留原文件。读取失败不覆盖原文件；CLI 仍使用单 Profile JSON。

旧配置 `use_server_routes: false` 在缺省、`gateway_only` 或 `merge` 策略下按 `manual_only` 处理。手动值仅在 `merge` / `manual_only` 下校验、应用。

主密码/OTP/会话密钥使用 `zeroize` 尽力清理，无法保证系统换页和库内部缓冲全部擦除。保存到本地的内容不上传云端，但需保护文件和备份。软件设置只读查询适配器：Unix 使用 `getifaddrs` 和 MTU 查询，Windows 使用固定 PowerShell/.NET 查询（5 秒、1 MiB 上限）；虚拟接口标记不代表该接口属于 SSLRay。

## macOS 打包

[打包脚本](../scripts/bundle-macos.sh)需要 Python 3.11+，运行客户端不需要 Python。脚本重建 `Frameworks`、捆绑 TLS 库并做 ad-hoc 签名，从主程序及所带动态库的 Mach-O 声明计算最高的最低系统版本；无法读取则失败。当前开发包为 Apple Silicon / macOS 26.0+。降低 Rust 部署目标不能降低预编译库的系统要求，旧系统需重建后端并实测。

签名前收集本机构建的许可文本；静态 TLS 构建应以 `SSLRAY_TLS_SOURCE_DIR` 指定实际源码目录。收集范围和缺失项见[第三方说明](THIRD-PARTY.md)。Linux/Windows、全隧道及异常退出的验收范围见[验证状态](VALIDATION.md)。
