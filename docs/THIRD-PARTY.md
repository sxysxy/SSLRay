# 随附第三方源码

原生 OpenVPN 后端包含 [Omnitun](https://github.com/GarageDeveloper/omnitun) 的以下三个 Rust crate，固定版本 0.4.5、提交 `d117595bdf1700faf14410e83cfd9676b7d5834d`：

| crate | 本地位置 | 用途 |
|---|---|---|
| vpn-openvpn | `third_party/omnitun/crates/vpn-openvpn` | OpenVPN 控制通道、认证、数据加密、可靠传输、会话 |
| vpn-core | `third_party/omnitun/crates/vpn-core` | 引擎、配置、交互与网络设置公共类型 |
| vpn-tls | `third_party/omnitun/crates/vpn-tls` | 客户端证书签名与 TLS 辅助类型 |

上游标注 **MIT OR Apache-2.0**，版权为 **Copyright (c) 2026 GarageDeveloper and the Omnitun contributors**。原始 [MIT](../third_party/omnitun/LICENSE-MIT) 与 [Apache-2.0](../third_party/omnitun/LICENSE-APACHE) 全文随源码保留；来源与本地修改记录见 [UPSTREAM.md](../third_party/omnitun/UPSTREAM.md)。SSLRay 未引入 Omnitun 的 GUI、守护进程、平台安装程序或第三方二进制。

macOS 打包脚本会在签名前把上述两份许可证及来源说明复制到应用内的 `Contents/Resources/ThirdPartyLicenses/Omnitun`，并附上 SSLRay 自身许可证和本说明。

`scripts/collect-licenses.py` 从实际配置的静态 TLS 源码或已链接动态库的安装目录收集声明，并用本次构建目录的 rustc `.d` 记录筛选 `Cargo.lock` 中的依赖，从本机 registry 源码收集其 LICENSE、COPYING、NOTICE 和字体许可文本。保留嵌套路径，包括默认字体的 OFL、UFL、Hack 和 emoji 声明。该步骤不调用 Cargo、不访问网络；源码或独立许可文件缺失时，将缺口记录在应用内的 `ThirdPartyLicenses/INDEX.json`。

记录描述本地实际收集的文件，不承诺完整覆盖所有传递依赖或完成法务审核。rustls、ring、Tokio、OpenSSL 等仍按各自许可证发布，其确切版本见 `Cargo.lock`。构建目录可能保留之前特性组合及构建工具的记录；收集结果也可能包含这些声明。

## OpenSSL

官方 [openssl/openssl](https://github.com/openssl/openssl) 以 Git submodule 位于 `third_party/openssl`，固定标签 `openssl-4.0.3`、提交 `af1775b60dfa141a4ad762585052cabeb9f37e9e`，不跟随 master。该版本来自 [4.0 维护分支](https://www.openssl-library.org/source/)，许可为 [Apache-2.0](../third_party/openssl/LICENSE.txt)。macOS 默认静态编译该源码；原始许可及 NOTICE 随应用收集。子模块不包含用户凭据，构建产物位于忽略的 `work/`。

构建前按 `openssl-source.json` 重算完整 Git tree，核对文件、可执行位与符号链接；完整源码 ZIP 无需 `.git` 也可校验。11 个上游可选测试/provider 子模块未下载、不参与 `no-tests` 构建。更新时需显式切换并记录提交，同步校验元数据，再运行 TLS、国密和平台构建检查。
