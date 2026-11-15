# Wintun 0.14.1 预编译文件来源

SSLRay 的 Windows helper 固定接受官方 Wintun 0.14.1 归档中与目标架构匹配的原始 `wintun.dll`。本目录只保存来源记录和原始许可证，不收录 DLL。

- 官方项目与下载说明：[wintun.net](https://www.wintun.net/)
- 官方归档：[wintun-0.14.1.zip](https://www.wintun.net/builds/wintun-0.14.1.zip)
- 归档 SHA-256：`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`
- 原始许可：归档中的 `wintun/LICENSE.txt`，按原始字节保存为本目录的 [LICENSE.txt](LICENSE.txt)
- 许可文件 SHA-256：`183adac21e7d96c508c8fd34d394b7b6708bc81564ad1bad61ab66143a008cd2`

以下哈希由核对过上述 SHA-256 的官方 ZIP 直接计算；路径相对于 ZIP 根目录。这是归档文件清单，不代表全部架构均已完成 SSLRay 构建或运行验收。

| 架构 | 归档路径 | DLL SHA-256 |
| --- | --- | --- |
| AMD64 | `wintun/bin/amd64/wintun.dll` | `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce` |
| X86 | `wintun/bin/x86/wintun.dll` | `d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931` |
| ARM64 | `wintun/bin/arm64/wintun.dll` | `f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80` |
| ARM32 | `wintun/bin/arm/wintun.dll` | `daad267411ecdc70a0535e274d2c3e9da3d0084bdac7662cb8424dd4a031b4d9` |

Windows 分发时，将目标架构的原始 DLL 放在 `sslray.exe` 旁，并随包保留完整 [Prebuilt Binaries License](LICENSE.txt)。该预编译许可与项目源码的 GPL 2.0 许可不同；以许可全文为准。

helper 保持仅共享读取的文件句柄并防止目录被替换，先核对固定内容哈希，再用 `WinVerifyTrust` 按本机信任策略离线验证签名；不弹窗或联网检索，也不宣称完成在线吊销检查。通过后才从明确的绝对路径加载 DLL，依赖库搜索限于系统目录。更新 Wintun 时，需显式核对新的官方归档、许可证和各架构 DLL 哈希，再同步加载器和本说明，并完成 Windows 构建及运行检查。
