# Nephele Core Audit

Auditable subset of the [Nephele Workshop](https://nephele.arisfusion.com) client, covering the security-critical modules: digital evidence packaging, perceptual / blind watermarking, and AI-metadata detection.

This repository exists so anyone — security researchers, lawyers, fellow artists — can inspect and reproduce the exact code that runs inside the desktop application's evidence and rights pipeline, without having to disassemble the packed Windows build.

## Scope

This is **not** the full client. It contains only the modules referenced by the public [Technical Audit Document](https://nephele.arisfusion.com/docs/security/audit):

| Module | Files | Purpose |
|:---|:---|:---|
| Digital evidence | `rights/logic.py`, `rights/utils.py`, `rights/tsa_client.py`, `rights/rights_packer.py`, `rights/url_evidence.py` | SHA-256 hashing, Merkle Tree, RFC 3161 TSA, `.nep` container, URL evidence capture |
| Browser capture | `browser/session.py` | Playwright session and screenshot helper used by URL evidence |
| Watermark | `packer/watermark_protection.py`, `packer/logic.py`, `packer/agent_api.py`, `workers/watermark_worker.py` | Blind watermark embed / extract, fixed-length encoding, round-trip verification |
| AI metadata detection | `validator/logic.py`, `validator/c2pa_verifier.py`, `workers/ai_detector_worker.py` | EXIF / XMP / C2PA parsing, rule matching, evidence grading |

Out of scope (each has its own threat model and is not published here):

- Authentication, JWT, CAPTCHA (`core/auth/`)
- Licensing and payment (`core/license_manager.py`, `core/payment.py`)
- AI agent loop and cloud inference (`core/agent_loop.py`, server side)
- Updater and SSL pinning (`core/updater.py`, `core/ssl_pinning.py`)

## Versioning

Each tag in this repository corresponds to a Nephele Workshop client release (e.g. `v0.3.2-alpha`). The audit document on the website pins to a specific commit / tag and renders the source from this repository at build time.

The mapping back to the upstream tree is preserved by directory name:

```
rights/        ←  tools/rights/        in the client tree
packer/        ←  tools/packer/        in the client tree
validator/     ←  tools/validator/     in the client tree
browser/       ←  core/browser/        in the client tree
workers/       ←  core/workers/        in the client tree
```

## License

MIT — see [LICENSE](LICENSE). Free to copy, modify, redistribute. Attribution preserved is appreciated but not required.

## What this repository is not

- Not a runnable Python package. Files keep their original imports (e.g. `from .utils import ...`); they will not import standalone outside the full client without rewriting paths.
- Not a guarantee of bit-for-bit identity with the shipped binary. Verification of the desktop build is a separate, known-hard problem (Nuitka standalone). This repository lets you read what was *intended* to ship; combined with the public release notes and the deterministic outputs (Merkle root, TSA token, watermark round-trip) you can sanity-check the build behaviour against this source.

## Reporting issues

Audit findings, cryptographic concerns, or implementation bugs:

- Open an issue on this repository, or
- Email security at the address listed on the [website](https://nephele.arisfusion.com)

Functional pull requests are not accepted here — this is a downstream mirror of the client tree. File them upstream against the main product.
