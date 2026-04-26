<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/CreatorAris/CreatorAris/dist/github-snake-dark.svg" />
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/CreatorAris/CreatorAris/dist/github-snake.svg" />
  <img alt="github contribution snake animation" src="https://raw.githubusercontent.com/CreatorAris/CreatorAris/dist/github-snake.svg" />
</picture>

# Nephele Core Audit

Auditable subset of the [Nephele Workshop](https://nephele.arisfusion.com) client — digital evidence, watermarking, AI-metadata detection.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.10-blue.svg)](https://www.python.org)
[![Tracks](https://img.shields.io/badge/tracks-v0.3.2--alpha-purple.svg)](https://nephele.arisfusion.com/changelog)
[![GitHub stars](https://img.shields.io/github/stars/CreatorAris/nephele-core-audit.svg)](https://github.com/CreatorAris/nephele-core-audit/stargazers)
[![GitHub last commit](https://img.shields.io/github/last-commit/CreatorAris/nephele-core-audit.svg)](https://github.com/CreatorAris/nephele-core-audit/commits)

[中文文档](README_ZH.md) · [Audit document](https://nephele.arisfusion.com/docs/security/audit)

</div>

## What this is

This repository mirrors the security-critical Python modules of the [Nephele Workshop](https://nephele.arisfusion.com) desktop client. It exists so that anyone — security researchers, lawyers, fellow artists — can read and reproduce the exact code that runs inside the evidence and rights pipeline, without having to disassemble the packed Windows build.

The public [Technical Audit Document](https://nephele.arisfusion.com/docs/security/audit) renders code from this repository at build time, pinned to a specific commit. Every snippet in the doc has a "GitHub" link that points back to the exact line range, at the exact revision, in this tree.

## Scope

Only the modules referenced by the audit document are published here.

| Module | Files | Purpose |
|:---|:---|:---|
| Digital evidence | `rights/logic.py`, `rights/utils.py`, `rights/tsa_client.py`, `rights/rights_packer.py`, `rights/url_evidence.py` | SHA-256 hashing, Merkle Tree, RFC 3161 TSA client, `.nep` container, URL evidence capture |
| Browser capture | `browser/session.py` | Playwright session + screenshot helpers used by URL evidence |
| Watermark | `packer/watermark_protection.py`, `packer/logic.py`, `packer/agent_api.py`, `workers/watermark_worker.py` | Blind watermark embed / extract, fixed-length encoding, round-trip verification |
| AI metadata detection | `validator/logic.py`, `validator/c2pa_verifier.py`, `workers/ai_detector_worker.py` | EXIF / XMP / C2PA parsing, rule matching, evidence grading |

Out of scope (each has its own threat model, not published here):

- Authentication, JWT, CAPTCHA (`core/auth/`)
- Licensing and payment (`core/license_manager.py`, `core/payment.py`)
- AI agent loop and cloud inference (`core/agent_loop.py`, server side)
- Updater and SSL pinning (`core/updater.py`, `core/ssl_pinning.py`)

## Versioning

Each tag in this repository corresponds to a Nephele Workshop client release (e.g. `v0.3.2-alpha`). The audit document on the website pins to a specific commit / tag and renders the source from this repository at build time.

Mapping back to the upstream tree is preserved by directory name:

```
rights/      <-  tools/rights/      in the client tree
packer/      <-  tools/packer/      in the client tree
validator/   <-  tools/validator/   in the client tree
browser/     <-  core/browser/      in the client tree
workers/     <-  core/workers/      in the client tree
```

## How to read this code

This is not a runnable Python package. Files keep their original imports (e.g. `from .utils import ...`); they will not import standalone outside the full client without rewriting paths. The intent is reading, not running.

For an annotated walkthrough — what each function is, what threat model it operates under, what the known limitations are — see the [Technical Audit Document](https://nephele.arisfusion.com/docs/security/audit). It quotes from this repository, section by section, with safety analysis.

## What this repository is not

- Not a guarantee of bit-for-bit identity with the shipped binary. Reproducible builds for Nuitka-packed Windows binaries is a separate, hard problem and is not solved here.
- Not the entire client. Only the audit-targeted subset is mirrored.
- Not the upstream development tree. Patches land in the client repository first; this mirror is updated on each tagged client release.

## Reporting issues

Audit findings, cryptographic concerns, or implementation bugs:

- Open an issue on this repository, or
- Email security at the address listed on the [website](https://nephele.arisfusion.com)

Functional pull requests are not accepted here — this is a downstream mirror of the client tree. File them upstream against the main product.

## License

MIT, see [LICENSE](LICENSE). Free to copy, modify, redistribute. Attribution preserved is appreciated but not required.

## Related repositories

- [nephele-verify](https://github.com/CreatorAris/nephele-verify) — independent verification page for `.nep` evidence files
- [nephele-wisp](https://github.com/CreatorAris/nephele-wisp) — browser-side companion (Chrome / Edge extension)
