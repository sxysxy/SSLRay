# 随附第三方源码

原生 OpenVPN 后端包含 [Omnitun](https://github.com/GarageDeveloper/omnitun) 的以下三个 Rust crate，固定版本 0.4.5、提交 `d117595bdf1700faf14410e83cfd9676b7d5834d`：

| crate | 本地位置 | 用途 |
|---|---|---|
| vpn-openvpn | `third_party/omnitun/crates/vpn-openvpn` | OpenVPN 控制通道、认证、数据加密、可靠传输、会话 |
| vpn-core | `third_party/omnitun/crates/vpn-core` | 引擎、配置、交互与网络设置公共类型 |
| vpn-tls | `third_party/omnitun/crates/vpn-tls` | 客户端证书签名与 TLS 辅助类型 |

上游标注 **MIT OR Apache-2.0**，版权为 **Copyright (c) 2026 GarageDeveloper and the Omnitun contributors**。原始 [MIT](../third_party/omnitun/LICENSE-MIT) 与 [Apache-2.0](../third_party/omnitun/LICENSE-APACHE) 全文随源码保留；来源与本地修改记录见 [UPSTREAM.md](../third_party/omnitun/UPSTREAM.md)。SSLRay 未引入 Omnitun 的 GUI、守护进程、平台安装程序或第三方二进制。

macOS 打包脚本会在签名前把上述两份许可证及来源说明复制到应用内的 `Contents/Resources/ThirdPartyLicenses/Omnitun`，并附上 SSLRay 自身许可证和本说明。

`scripts/collect-licenses.py` 根据实际链接动态库的安装目录收集 OpenSSL 声明，并用本次构建目录的 rustc `.d` 记录筛选 `Cargo.lock` 中的依赖，从本机 registry 源码收集其 LICENSE、COPYING、NOTICE 和字体许可文本。保留嵌套路径，包括默认字体的 OFL、UFL、Hack 和 emoji 声明。该步骤不调用 Cargo、不访问网络；源码或独立许可文件缺失时，将缺口记录在应用内的 `ThirdPartyLicenses/INDEX.json`。

记录描述本地实际收集的文件，不承诺完整覆盖所有传递依赖或完成法务审核。rustls、ring、Tokio、OpenSSL 等仍按各自许可证发布，其确切版本见 `Cargo.lock`。构建目录可能保留之前特性组合及构建工具的记录；收集结果也可能包含这些声明。
