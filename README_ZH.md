<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/CreatorAris/CreatorAris/dist/github-snake-dark.svg" />
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/CreatorAris/CreatorAris/dist/github-snake.svg" />
  <img alt="github contribution snake animation" src="https://raw.githubusercontent.com/CreatorAris/CreatorAris/dist/github-snake.svg" />
</picture>

# Nephele Core Audit

[Nephele Workshop](https://nephele.arisfusion.com) 客户端的可审计子集 —— 数字存证、隐水印、AI 元数据检测。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.10-blue.svg)](https://www.python.org)
[![Tracks](https://img.shields.io/badge/tracks-v0.3.2--alpha-purple.svg)](https://nephele.arisfusion.com/changelog)
[![GitHub stars](https://img.shields.io/github/stars/CreatorAris/nephele-core-audit.svg)](https://github.com/CreatorAris/nephele-core-audit/stargazers)
[![GitHub last commit](https://img.shields.io/github/last-commit/CreatorAris/nephele-core-audit.svg)](https://github.com/CreatorAris/nephele-core-audit/commits)

[English](README.md) · [审计白皮书](https://nephele.arisfusion.com/docs/security/audit)

</div>

## 这是什么

本仓库镜像了 [Nephele Workshop](https://nephele.arisfusion.com) 桌面客户端中安全相关的 Python 模块，包括数字存证、隐水印、AI 元数据检测三块核心代码。开源此仓库的目的是让任何人 —— 安全研究者、律师、其他画师 —— 都能直接阅读并复现客户端实际运行的代码，而不必反编译已打包的 Windows 构建。

公开的 [技术审计文档](https://nephele.arisfusion.com/docs/security/audit) 在构建期从本仓库读取源码渲染，并锁定到一个固定 commit。文档里每一段代码块都带 "GitHub" 链接，指向本仓库该 commit 下的精确行号区间。

## 范围

只包含审计文档引用过的模块。

| 模块 | 文件 | 职责 |
|:---|:---|:---|
| 数字存证 | `rights/logic.py`、`rights/utils.py`、`rights/tsa_client.py`、`rights/rights_packer.py`、`rights/url_evidence.py` | SHA-256 哈希、Merkle Tree、RFC 3161 TSA 客户端、`.nep` 容器、URL 取证 |
| 浏览器抓取 | `browser/session.py` | URL 取证用到的 Playwright 会话与截图辅助 |
| 隐水印 | `packer/watermark_protection.py`、`packer/logic.py`、`packer/agent_api.py`、`workers/watermark_worker.py` | 盲水印嵌入与提取、定长编码、round-trip 验证 |
| AI 元数据检测 | `validator/logic.py`、`validator/c2pa_verifier.py`、`workers/ai_detector_worker.py` | EXIF / XMP / C2PA 解析、规则匹配、证据分级 |

不在本仓库范围内（各自有独立威胁模型，不公开）：

- 认证、JWT、CAPTCHA（`core/auth/`）
- 许可证与支付（`core/license_manager.py`、`core/payment.py`）
- AI Agent 循环与云端推理（`core/agent_loop.py`、服务端代码）
- 客户端更新与 SSL 固定（`core/updater.py`、`core/ssl_pinning.py`）

## 版本对应

本仓库的每个 tag 对应一个 Nephele Workshop 客户端发布版本（例如 `v0.3.2-alpha`）。网站上的审计文档锁定到某个具体 commit / tag，构建期从本仓库读取源码。

目录结构与上游客户端代码树的映射关系：

```
rights/      <-  tools/rights/      （客户端代码树）
packer/      <-  tools/packer/      （客户端代码树）
validator/   <-  tools/validator/   （客户端代码树）
browser/     <-  core/browser/      （客户端代码树）
workers/     <-  core/workers/      （客户端代码树）
```

## 如何阅读本仓库代码

本仓库不是可独立运行的 Python 包。文件保留了原始的 import 路径（例如 `from .utils import ...`），如果不重写路径，单独 import 是无法运行的。本仓库的目的是供阅读，而不是供运行。

如果你需要带注释的逐节解读 —— 每个函数的职责、面对的威胁模型、已知限制 —— 请阅读 [技术审计文档](https://nephele.arisfusion.com/docs/security/audit)。文档按章节引用本仓库，并附有安全分析。

## 本仓库不是

- 不保证与发布的二进制文件逐字节一致。Nuitka 打包的 Windows 二进制可复现构建是另一个独立的难题，本仓库不解决该问题。
- 不是完整客户端代码，只是审计相关子集。
- 不是上游开发主线。补丁先合并到客户端主仓库，每次客户端打 tag 后再同步到本仓库。

## 反馈

审计发现、密码学问题、实现 bug：

- 在本仓库提 issue，或
- 发邮件到 [官网](https://nephele.arisfusion.com) 上列出的安全联系地址

不接受功能性 PR —— 本仓库是客户端代码的下游镜像，请到主项目提 PR。

## License

MIT，见 [LICENSE](LICENSE)。可自由复制、修改、再分发；保留版权声明即可。

## 相关仓库

- [nephele-verify](https://github.com/CreatorAris/nephele-verify) —— `.nep` 存证文件的独立验证页
- [nephele-wisp](https://github.com/CreatorAris/nephele-wisp) —— 浏览器侧伴侣（Chrome / Edge 扩展）
