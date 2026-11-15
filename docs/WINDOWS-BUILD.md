# Windows x64 原生构建与打包

这些入口在普通用户的 Windows PowerShell 5.1+ 中运行，不安装工具、不下载文件、不注册服务、不永久修改 PATH。它们只在当前进程导入 Visual Studio 开发环境，在项目 `work/` 内生成 OpenSSL 和 Cargo 缓存。构建/打包不启动 GUI，不申请 UAC，不连接 VPN 或修改路由。

需要 Rust MSVC 工具链、Visual Studio 的 C++ x64 工具与 Windows SDK、Python 3.11+、Git、原生 Windows Perl。推荐 OpenSSL 上游说明中的 Strawberry Perl；Git 自带的 MSYS Perl 不适用。可通过 `-PerlPath`、`-PythonPath`、`-VsDevCmdPath` 明确指定工具。脚本会发现标准的 Strawberry 安装路径及 `vswhere`；不需要 CMake 或 NASM。

先由用户初始化项目固定的 OpenSSL 子模块，避免 Git 在 Windows 上转换源文件换行：

```powershell
git -c core.autocrlf=false submodule update --init third_party/openssl
```

只初始化顶层子模块即可，不需要其可选测试仓库。Windows 校验器从固定 Git commit/tree 取得文件模式与 blob 清单，逐文件核对实际原始内容，并拒绝新增生成文件。由于 NTFS 不保留 POSIX 执行位，此入口要求 OpenSSL 的 Git 元数据。本项目完整源码归档解压为 `SSLRay/`，已包含所需 OpenSSL 公开浅 Git 数据、锁定的 Cargo 依赖及离线配置，可跳过初始化步骤；其它没有 `.git` 的源码导出应先取得固定子模块 checkout。校验失败时脚本不会更改或修复源码。

以下使用示例工具路径，按实际安装位置替换：

```powershell
$tools = @{
    PythonPath = 'C:\Python314\python.exe'
    PerlPath = 'C:\Strawberry\perl\bin\perl.exe'
    VsDevCmdPath = 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat'
}

# 开发和测试：自动准备固定静态后端。
.\scripts\cargo-windows.ps1 @tools -CargoArgs @('test', '--workspace', '--locked')

# 单独准备后端。
.\scripts\build-tls-windows.ps1 @tools

# 先自行取得并核验官方 Wintun 归档，再指定解压后的 wintun 目录。
.\scripts\bundle-windows.ps1 @tools -WintunRoot 'C:\Downloads\wintun-0.14.1\wintun'
```

OpenSSL 使用项目固定版本（见 `third_party/openssl-source.json`），从独立目录以 `VC-WIN64A no-shared no-module no-tests no-asm enable-static-vcruntime enable-sm2 enable-sm3 enable-sm4` 构建，安装到 `work/openssl-windows-x64-static-noasm/install`。当前入口明确禁用汇编，不隐式使用未发现的 NASM。配置、编译器、SDK、Perl、脚本内容及产物哈希参与缓存判定。每次使用都重新核对源码、AMD64 PE、静态 TLS/CRT 依赖及两个 SM4 TLS 1.3 套件。

Cargo 入口配置本次进程的 `OPENSSL_DIR`、`OPENSSL_STATIC=1` 及对应 target 变量，并通过 `CARGO_ENCODED_RUSTFLAGS` 追加 `-C target-feature=+crt-static`；保留已有显式 Rust 参数。默认 target 为 `x86_64-pc-windows-msvc`，输出在 `work/windows-x64-target/`。这些脚本目前只支持 MSVC x64，不宣称已验证 ARM64、x86 或 MinGW 构建。

打包读取 workspace 版本，核对 CLI 版本/加密能力，拒绝动态 OpenSSL 与 VC/UCRT 运行库导入。Wintun 必须是 [0.14.1 官方来源记录](../third_party/wintun/README.md) 中的原始 AMD64 DLL；DLL 与许可证都按固定 SHA-256 核验，并检查 DLL 的 PE 架构与本机 Authenticode 验证结果。脚本不下载 Wintun，也不替换它的原始签名。

输出为 `dist/SSLRay/` 和 `dist/SSLRay-<版本>-windows-x64.zip`（可用 `-OutputDirectory` 指定新目录）。ZIP 只有一个 `SSLRay/` 根目录，解压后运行 `SSLRay/SSLRay.exe`；同目录含 `wintun.dll`、Wintun 原始许可、项目及实际依赖的通知、构建记录和 SHA-256。ZIP 解压后逐文件对比；已有同名输出时拒绝覆盖。通知收集器的范围与缺项在 `ThirdPartyLicenses/INDEX.json` 中明确列出。

脚本不签署客户端 EXE；实际签名状态写入 `build-info.json` 和 README。Wintun 的官方签名不代表客户端 EXE 已签名。构建、静态依赖、能力和打包检查不代表完成了 UAC、Wintun 创建、真实 VPN 及路由清理的实机验收；后者应单独记录。
