# 随附第三方源码

原生 OpenVPN 后端包含 [Omnitun](https://github.com/GarageDeveloper/omnitun) 的以下三个 Rust crate，固定版本 0.4.5、提交 `d117595bdf1700faf14410e83cfd9676b7d5834d`：

| crate | 本地位置 | 用途 |
|---|---|---|
| vpn-openvpn | `third_party/omnitun/crates/vpn-openvpn` | OpenVPN 控制通道、认证、数据加密、可靠传输、会话 |
| vpn-core | `third_party/omnitun/crates/vpn-core` | 引擎、配置、交互与网络设置公共类型 |
| vpn-tls | `third_party/omnitun/crates/vpn-tls` | 客户端证书签名与 TLS 辅助类型 |

上游标注 **MIT OR Apache-2.0**，版权为 **Copyright (c) 2026 GarageDeveloper and the Omnitun contributors**。原始 [MIT](../third_party/omnitun/LICENSE-MIT) 与 [Apache-2.0](../third_party/omnitun/LICENSE-APACHE) 全文随源码保留；来源与本地修改记录见 [UPSTREAM.md](../third_party/omnitun/UPSTREAM.md)。SSLRay 未引入 Omnitun 的 GUI、守护进程、平台安装程序或第三方二进制。

macOS 打包脚本会在签名前把上述两份许可证及来源说明复制到应用内的 `Contents/Resources/ThirdPartyLicenses/Omnitun`，并附上 SSLRay 自身许可证和本说明。

`scripts/collect-licenses.py` 从实际配置的静态 TLS 源码或已链接动态库的安装目录收集声明，并用本次构建目录的 rustc `.d` 记录筛选 `Cargo.lock` 中的依赖，从本机 registry 源码收集其 LICENSE、COPYING、NOTICE 和字体许可文本。保留嵌套路径，包括默认字体的 OFL、UFL、Hack 和 emoji 声明。对 crate 打包遗漏的上游声明，另从 [license-notices](../third_party/license-notices/README.md) 离线补充；映射严格绑定版本、crate SHA-256、仓库及发布时的 VCS 提交/路径，并校验声明文件哈希。来源与原始文件逐项记录在应用内 `ThirdPartyLicenses/INDEX.json`，不修改 registry，也不在收集时调用 Cargo 或访问网络。

部分新版 objc2 依赖在对应上游提交中只提供授权政策链接，没有完整授权及版权文本；dispatch 0.2.0 未提供独立声明文件。收集结果在 `upstream_notice_limitations` 和缺失文件列表中保留这些真实上游缺口，不用通用模板或其他版本的版权声明冒充补齐。

记录描述本地实际收集的文件，不承诺完整覆盖所有传递依赖或完成法务审核。rustls、ring、Tokio、OpenSSL 等仍按各自许可证发布，其确切版本见 `Cargo.lock`。构建目录可能保留之前特性组合及构建工具的记录；收集结果也可能包含这些声明。

## OpenSSL

官方 [openssl/openssl](https://github.com/openssl/openssl) 以 Git submodule 位于 `third_party/openssl`，固定标签 `openssl-4.0.3`、提交 `af1775b60dfa141a4ad762585052cabeb9f37e9e`，不跟随 master。该版本来自 [4.0 维护分支](https://www.openssl-library.org/source/)，许可为 [Apache-2.0](../third_party/openssl/LICENSE.txt)。macOS 默认静态编译该源码；原始许可及 NOTICE 随应用收集。子模块不包含用户凭据，构建产物位于忽略的 `work/`。

构建前按 `openssl-source.json` 重算完整 Git tree，核对文件、可执行位与符号链接；完整源码 ZIP 无需 `.git` 也可校验。11 个上游可选测试/provider 子模块未下载、不参与 `no-tests` 构建。更新时需显式切换并记录提交，同步校验元数据，再运行 TLS、国密和平台构建检查。

## Wintun（Windows）

Windows helper 使用 [Wintun 官方 0.14.1 预编译归档](https://www.wintun.net/builds/wintun-0.14.1.zip) 中匹配目标架构的原始 `wintun.dll`。归档含 AMD64、X86、ARM64 和 ARM32 文件；各文件的 SHA-256 固定在加载器中，加载前先校验内容和 Windows 签名。详细来源、归档及 DLL 哈希见 [third_party/wintun/README.md](../third_party/wintun/README.md)。源码库不收录这些 DLL，Windows 分发包需另附匹配架构的原始 DLL 及完整许可证。

官方预编译 DLL 适用归档中的 [Prebuilt Binaries License](../third_party/wintun/LICENSE.txt)，此文件按原始字节保留。它与 Wintun 源码的 GPL 2.0 许可不同；分发和使用应遵守预编译许可全文，不应把 DLL 视为采用 SSLRay 主项目许可证的组件。Rust 接口依赖 `wintun-bindings` 仍遵循其自身许可。Windows 实机及各架构验收边界见[验证状态](VALIDATION.md)。
