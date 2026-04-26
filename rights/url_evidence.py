"""
Nephele Workshop - URL Evidence Capture
Captures and preserves web page evidence for copyright infringement cases.

Pipeline:
  1. Record environment info (IP, DNS, OS, app version)
  2. Navigate to target URL (Playwright headless)
  3. Full-page screenshot
  4. Save HTML source
  5. Extract and download images
  6. Compute SHA-256 + pHash for all artifacts
  7. Generate manifest.json
  8. Request RFC 3161 timestamp for manifest hash
  9. Package output directory

Developer: ArisFusion Studio
"""

import hashlib
import json
import logging
import platform
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .logic import RightsError

logger = logging.getLogger(__name__)


class URLEvidenceError(RightsError):
    """URL evidence capture error."""
    pass


class URLEvidenceCapture:
    """
    Captures web page evidence with tamper-proof packaging.

    All artifacts are hashed, timestamped, and bundled into an output directory
    with a manifest.json that ties everything together.
    """

    def __init__(
        self,
        output_dir: Path,
        tsa_provider: str = "digicert",
        tsa_timeout: int = 30,
    ):
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._tsa_provider = tsa_provider
        self._tsa_timeout = tsa_timeout
        self._log: List[str] = []
        self._evidence_id = str(uuid.uuid4())
        self._log_committed = False  # Set True after log is hashed into manifest

    def _record(self, message: str) -> None:
        """Append a timestamped entry to the operation log."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        entry = f"[{ts}] {message}"
        self._log.append(entry)
        logger.info("[URLEvidence] %s", message)

    # ===== Step 1: Environment =====

    def collect_environment(self) -> Dict:
        """Collect local environment info for the evidence record."""
        self._record("Collecting environment info")
        env = {
            "os": f"{platform.system()} {platform.release()}",
            "os_version": platform.version(),
            "hostname": platform.node(),
            "python_version": platform.python_version(),
        }

        # App version (best-effort)
        try:
            from _version import __version__
            env["nephele_version"] = __version__
        except ImportError:
            env["nephele_version"] = "dev"

        # Public IP (best-effort, no external call — just record local IPs)
        try:
            env["local_ip"] = socket.gethostbyname(socket.gethostname())
        except Exception:
            env["local_ip"] = "unknown"

        self._record(f"Environment: {env['os']}, Nephele {env['nephele_version']}")
        return env

    # ===== Step 1b: TLS certificate =====

    def capture_tls_certificate(self, url: str) -> Dict:
        """
        Capture the server's TLS certificate chain.
        This proves the connection was made to the authentic server —
        you can't forge a CA-signed certificate.
        """
        import ssl
        from urllib.parse import urlparse

        self._record("Capturing TLS server certificate")
        parsed = urlparse(url if "://" in url else f"https://{url}")
        hostname = parsed.hostname or ""
        port = parsed.port or 443

        if not hostname:
            return {"error": "Invalid hostname"}

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                server_hostname=hostname,
            ) as sock:
                sock.settimeout(10)
                sock.connect((hostname, port))
                cert = sock.getpeercert()
                cert_der = sock.getpeercert(binary_form=True)

            # Save DER certificate to file
            cert_path = self._output_dir / "server_certificate.der"
            cert_path.write_bytes(cert_der)

            # Also save human-readable PEM
            import base64
            pem_data = (
                "-----BEGIN CERTIFICATE-----\n"
                + base64.encodebytes(cert_der).decode()
                + "-----END CERTIFICATE-----\n"
            )
            pem_path = self._output_dir / "server_certificate.pem"
            pem_path.write_text(pem_data, encoding="utf-8")

            # Extract key fields
            subject = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            cert_info = {
                "subject_cn": subject.get("commonName", ""),
                "issuer_cn": issuer.get("commonName", ""),
                "issuer_org": issuer.get("organizationName", ""),
                "not_before": cert.get("notBefore", ""),
                "not_after": cert.get("notAfter", ""),
                "serial_number": cert.get("serialNumber", ""),
                "san": [
                    entry[1]
                    for entry in cert.get("subjectAltName", ())
                    if entry[0] == "DNS"
                ],
                "der_path": str(cert_path),
                "pem_path": str(pem_path),
                "der_sha256": hashlib.sha256(cert_der).hexdigest(),
            }

            self._record(
                f"TLS cert captured: {cert_info['subject_cn']} "
                f"(issuer: {cert_info['issuer_org']}, "
                f"serial: {cert_info['serial_number'][:16]}...)"
            )
            return cert_info

        except Exception as e:
            self._record(f"TLS certificate capture failed: {e}")
            return {"error": str(e)}

    # ===== Step 2: DNS resolution =====

    def resolve_dns(self, url: str) -> Dict:
        """Resolve the target URL's hostname to IP addresses."""
        from urllib.parse import urlparse
        self._record(f"Resolving DNS for: {url}")

        parsed = urlparse(url if "://" in url else f"https://{url}")
        hostname = parsed.hostname or ""
        if not hostname:
            return {"hostname": "", "addresses": [], "error": "Invalid URL"}

        try:
            results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
            addresses = list({r[4][0] for r in results})
            self._record(f"DNS resolved: {hostname} -> {addresses}")
            return {"hostname": hostname, "addresses": addresses}
        except socket.gaierror as e:
            self._record(f"DNS resolution failed: {e}")
            return {"hostname": hostname, "addresses": [], "error": str(e)}

    # ===== Step 3-5: Browser capture =====

    # CAPTCHA / anti-bot keywords in page title
    _CAPTCHA_KEYWORDS = (
        "验证码", "验证", "captcha", "verify", "challenge",
        "human verification", "robot", "机器人",
    )

    def _is_captcha_page(self, title: str, url: str) -> bool:
        """Detect if the loaded page is a CAPTCHA or anti-bot challenge."""
        text = (title or "").lower()
        url_lower = (url or "").lower()
        for kw in self._CAPTCHA_KEYWORDS:
            if kw in text or kw in url_lower:
                return True
        return False

    def capture_page(
        self,
        url: str,
        progress_callback=None,
    ) -> Dict:
        """
        Navigate to URL and capture screenshot + HTML + images.

        Uses the existing BrowserManager singleton (Playwright Chromium).
        If the page shows a CAPTCHA, switches to visible mode so the user
        can solve it, then resumes automated capture.

        Args:
            url: Target URL
            progress_callback: Optional (step, total, message) callback

        Returns:
            Dict with paths to captured artifacts
        """
        from core.browser.session import BrowserManager

        mgr = BrowserManager.instance()
        if not mgr.ensure_browser(headless=True):
            raise URLEvidenceError(
                "Playwright browser unavailable. Install with: pip install playwright && playwright install chromium"
            )

        artifacts = {}
        total_steps = 5

        # Enable HAR recording — captures full HTTP request/response traffic
        har_path = self._output_dir / "network.har"
        har_result = mgr.create_evidence_context(str(har_path))
        if har_result.get("success"):
            self._record(f"HAR recording enabled: {har_path.name}")
        else:
            self._record(f"HAR recording unavailable (non-fatal): {har_result.get('message')}")

        # Step 3a: Navigate (headless first)
        if progress_callback:
            progress_callback(1, total_steps, "Navigating to target URL...")
        self._record(f"Navigating to: {url}")

        nav_result = mgr.navigate(url, wait_until="networkidle", timeout_ms=45000)
        if not nav_result.get("success"):
            raise URLEvidenceError(f"Navigation failed: {nav_result.get('message')}")

        page_title = nav_result.get("title", "")
        final_url = nav_result.get("url", url)
        self._record(f"Page loaded: {page_title} ({final_url})")

        # Detect CAPTCHA / login wall → switch to visible mode for user to solve
        needs_interaction = (
            nav_result.get("login_required", False)
            or self._is_captcha_page(page_title, final_url)
        )

        if needs_interaction:
            self._record(f"CAPTCHA/login wall detected: {page_title}")
            self._record("Switching to visible browser for user interaction")

            if progress_callback:
                progress_callback(1, total_steps, "Detected CAPTCHA, opening browser...")

            # Close headless, reopen visible
            mgr.close()
            if not mgr.ensure_browser(headless=False):
                raise URLEvidenceError("Failed to open visible browser")

            # Navigate again in visible mode
            nav_result = mgr.navigate(url, wait_until="networkidle", timeout_ms=45000)
            page_title = nav_result.get("title", "")
            final_url = nav_result.get("url", url)

            # Wait for user to solve CAPTCHA (poll page title change)
            if progress_callback:
                progress_callback(1, total_steps, "Waiting for CAPTCHA...")
            self._record("Waiting for user to solve CAPTCHA...")

            import time
            max_wait = 120  # 2 minutes
            poll_interval = 2
            waited = 0
            while waited < max_wait:
                time.sleep(poll_interval)
                waited += poll_interval
                # Re-check page title
                try:
                    current_title = mgr._run(mgr._page.title())
                    current_url = mgr._page.url
                except Exception:
                    break
                if not self._is_captcha_page(current_title, current_url):
                    self._record(f"CAPTCHA solved, page now: {current_title}")
                    page_title = current_title
                    final_url = current_url
                    break

                if progress_callback:
                    remaining = max_wait - waited
                    progress_callback(
                        1, total_steps,
                        f"Waiting for CAPTCHA... ({remaining}s remaining)",
                    )
            else:
                self._record("CAPTCHA wait timeout, capturing current page state")

            # Wait for page to fully load after CAPTCHA
            try:
                mgr._run(mgr._page.wait_for_load_state("networkidle", timeout=15000))
            except Exception:
                pass

            # Re-read final state
            try:
                page_title = mgr._run(mgr._page.title())
                final_url = mgr._page.url
            except Exception:
                pass

            self._record(f"Final page: {page_title} ({final_url})")

        artifacts["page_title"] = page_title
        artifacts["final_url"] = final_url
        artifacts["login_required"] = nav_result.get("login_required", False)
        artifacts["captcha_encountered"] = needs_interaction

        # Capture HTTP response headers from the main page
        # These are server-asserted values (Date, Server, ETag) that can't be forged locally
        try:
            response_headers = mgr._run(mgr._page.evaluate("""
                () => {
                    // performance API gives response headers for the main document
                    const entries = performance.getEntriesByType("navigation");
                    if (entries.length > 0) {
                        const nav = entries[0];
                        return {
                            response_status: nav.responseStatus || 0,
                            transfer_size: nav.transferSize || 0,
                            server_timing: nav.serverTiming ? nav.serverTiming.map(t => t.name + '=' + t.duration) : [],
                        };
                    }
                    return {};
                }
            """))
        except Exception:
            response_headers = {}

        # Also try fetching headers via a secondary HEAD request for richer data
        try:
            head_resp = mgr._run(mgr._page.request.head(final_url, timeout=10000))
            if head_resp:
                raw_headers = head_resp.headers
                # Keep only forensically relevant headers
                relevant_keys = {
                    "date", "server", "etag", "last-modified", "content-type",
                    "x-powered-by", "x-request-id", "x-cache", "cf-ray",
                    "x-served-by", "age", "via",
                }
                server_headers = {
                    k: v for k, v in raw_headers.items()
                    if k.lower() in relevant_keys
                }
                response_headers["server_headers"] = server_headers
                self._record(f"HTTP response headers captured: {list(server_headers.keys())}")
        except Exception as e:
            self._record(f"HTTP headers capture failed (non-fatal): {e}")

        # Save response headers to file
        if response_headers:
            try:
                headers_path = self._output_dir / "response_headers.json"
                with open(headers_path, "w", encoding="utf-8") as f:
                    json.dump(response_headers, f, indent=2, ensure_ascii=False, default=str)
                artifacts["response_headers_path"] = str(headers_path)
                artifacts["response_headers"] = response_headers
            except Exception as e:
                self._record(f"Failed to save response headers: {e}")

        # Step 3b: Full-page screenshot
        if progress_callback:
            progress_callback(2, total_steps, "Taking screenshot...")
        self._record("Taking full-page screenshot")

        screenshot_path = self._output_dir / "screenshot.png"
        ss_result = mgr.screenshot(str(screenshot_path))
        if ss_result.get("success"):
            artifacts["screenshot_path"] = str(screenshot_path)
            self._record(f"Screenshot saved: {screenshot_path.name}")
        else:
            self._record(f"Screenshot failed: {ss_result.get('message')}")

        # Step 3c: Save HTML source
        if progress_callback:
            progress_callback(3, total_steps, "Saving HTML source...")
        self._record("Saving HTML source")

        html_path = self._output_dir / "page.html"
        try:
            html_content = mgr._run(mgr._page.content())
            html_path.write_text(html_content, encoding="utf-8")
            artifacts["html_path"] = str(html_path)
            self._record(f"HTML saved: {len(html_content)} chars")
        except Exception as e:
            self._record(f"HTML save failed: {e}")

        # Step 3d: Save PDF (headless Chromium only)
        pdf_path = self._output_dir / "page.pdf"
        pdf_result = mgr.save_pdf(str(pdf_path))
        if pdf_result.get("success"):
            artifacts["pdf_path"] = str(pdf_path)
            self._record(f"PDF saved: {pdf_path.name}")

        # Step 4: Extract images
        if progress_callback:
            progress_callback(4, total_steps, "Extracting images...")
        self._record("Extracting images from page")

        img_result = mgr.extract_images(min_size=150)
        image_urls = []
        if img_result.get("success"):
            images_data = img_result.get("data", {}).get("images", [])
            image_urls = [img["src"] for img in images_data if img.get("src")]
            self._record(f"Found {len(image_urls)} images on page")

        # Step 5: Download images
        if progress_callback:
            progress_callback(5, total_steps, "Downloading images...")

        images_dir = self._output_dir / "images"
        downloaded_images = []

        if image_urls:
            images_dir.mkdir(exist_ok=True)
            self._record(f"Downloading {min(len(image_urls), 30)} images")

            cache_result = mgr.download_images_to_cache(image_urls[:30])
            cached_map = cache_result.get("cached", {})

            for idx, (img_url, local_cache) in enumerate(cached_map.items()):
                try:
                    src = Path(local_cache)
                    if src.exists():
                        dest = images_dir / f"img_{idx:03d}{src.suffix}"
                        import shutil
                        shutil.copy2(str(src), str(dest))
                        downloaded_images.append({
                            "original_url": img_url,
                            "local_path": str(dest),
                        })
                except Exception as e:
                    logger.debug("Failed to copy image %s: %s", img_url[:60], e)

            self._record(f"Downloaded {len(downloaded_images)} images")

        artifacts["images"] = downloaded_images

        # Close evidence context to finalize HAR file (triggers write to disk)
        har_close = mgr.close_evidence_context()
        if har_close.get("success") and har_path.exists():
            artifacts["har_path"] = str(har_path)
            self._record(f"HAR saved: {har_path.stat().st_size // 1024} KB")
        else:
            self._record("HAR finalization skipped")

        # If we switched to visible mode, close entirely
        if needs_interaction:
            self._record("Closing visible browser after evidence capture")
            mgr.close()

        return artifacts

    # ===== Step 6: Hash everything =====

    def hash_artifacts(self, artifacts: Dict) -> Dict:
        """
        Compute SHA-256 for all captured files + pHash for images.

        Returns:
            Dict of {relative_path: {sha256, phash?, size}}
        """
        self._record("Computing hashes for all artifacts")
        file_hashes = {}

        # Hash screenshot, HTML, PDF, HAR
        for key in ("screenshot_path", "html_path", "pdf_path", "har_path"):
            path_str = artifacts.get(key)
            if path_str:
                p = Path(path_str)
                if p.exists():
                    sha = self._sha256_file(p)
                    file_hashes[p.name] = {
                        "sha256": sha,
                        "size": p.stat().st_size,
                        "type": key.replace("_path", ""),
                    }

        # Hash + pHash extracted images
        for img_info in artifacts.get("images", []):
            local_path = img_info.get("local_path")
            if not local_path:
                continue
            p = Path(local_path)
            if not p.exists():
                continue

            entry = {
                "sha256": self._sha256_file(p),
                "size": p.stat().st_size,
                "type": "extracted_image",
                "original_url": img_info.get("original_url", ""),
            }

            # Compute perceptual hash (best-effort)
            try:
                from .fingerprint import compute_fingerprint
                fp = compute_fingerprint(p, file_sha256=entry["sha256"])
                entry["phash"] = fp.phash
                entry["dhash"] = fp.dhash
                entry["width"] = fp.width
                entry["height"] = fp.height
            except Exception as e:
                logger.debug("pHash failed for %s: %s", p.name, e)

            file_hashes[f"images/{p.name}"] = entry

        self._record(f"Hashed {len(file_hashes)} files")
        return file_hashes

    # ===== Step 7: Manifest =====

    def generate_manifest(
        self,
        target_url: str,
        environment: Dict,
        dns_info: Dict,
        artifacts: Dict,
        file_hashes: Dict,
        tls_info: Optional[Dict] = None,
    ) -> Dict:
        """Generate manifest.json tying all evidence together."""
        self._record("Generating manifest")

        capture_time = datetime.now(timezone.utc).isoformat()

        manifest = {
            "nephele_evidence_version": "1.1",
            "evidence_id": self._evidence_id,
            "target_url": target_url,
            "final_url": artifacts.get("final_url", target_url),
            "page_title": artifacts.get("page_title", ""),
            "capture_time_utc": capture_time,
            "environment": environment,
            "dns_resolution": dns_info,
            "tls_certificate": tls_info or {},
            "server_response_headers": artifacts.get("response_headers", {}),
            "captcha_encountered": artifacts.get("captcha_encountered", False),
            "files": [],
            "disclaimer": (
                "本取证数据由 Nephele Workshop 自动化采集，仅供参考。"
                "证据效力以司法机关认定为准。"
            ),
        }

        for rel_path, info in file_hashes.items():
            entry = {"filename": rel_path, **info}
            manifest["files"].append(entry)

        # Compute manifest's own hash (excluding manifest_sha256 field itself)
        # Verification procedure: remove "manifest_sha256" key, json.dumps with
        # sort_keys=True + ensure_ascii=False, then SHA-256 the UTF-8 bytes.
        manifest_json = json.dumps(manifest, ensure_ascii=False, sort_keys=True, default=str)
        manifest_sha256 = hashlib.sha256(manifest_json.encode("utf-8")).hexdigest()
        manifest["manifest_sha256"] = manifest_sha256
        manifest["manifest_sha256_note"] = (
            "To verify: remove 'manifest_sha256' and 'manifest_sha256_note' keys, "
            "json.dumps(sort_keys=True, ensure_ascii=False), SHA-256 the UTF-8 bytes."
        )

        # Write manifest to disk.
        # NOTE: We intentionally do NOT write a separate manifest_canonical.json.
        # The canonical form is reproducible by any verifier: remove "manifest_sha256"
        # and "manifest_sha256_note" keys, then json.dumps(sort_keys=True,
        # ensure_ascii=False) and SHA-256 the UTF-8 bytes.  Writing it as a separate
        # file would be redundant and was previously included in the .nep archive
        # without being tracked in file_hashes (circular dependency).
        manifest_path = self._output_dir / "manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=False, default=str)

        self._record(f"Manifest saved (sha256={manifest_sha256[:16]}...)")
        return manifest

    # ===== Step 8: Timestamp =====

    def timestamp_manifest(self, manifest: Dict) -> Dict:
        """Request RFC 3161 timestamp for the manifest hash."""
        manifest_sha256 = manifest.get("manifest_sha256", "")
        if not manifest_sha256:
            self._record("No manifest hash to timestamp")
            return {"success": False, "message": "No manifest hash"}

        self._record("Requesting RFC 3161 timestamp for manifest")
        tsa_path = self._output_dir / "manifest.tsa"

        try:
            from .tsa_client import TSAClient
            client = TSAClient(
                provider=self._tsa_provider,
                timeout=self._tsa_timeout,
            )
            result = client.timestamp_hash(manifest_sha256, tsa_path)
            if result.get("success"):
                self._record(f"TSA timestamp obtained: {result.get('issuer')}")
                return {
                    "success": True,
                    "tsa_path": str(tsa_path),
                    "timestamp": result.get("timestamp"),
                    "issuer": result.get("issuer"),
                }
            else:
                self._record(f"TSA failed: {result.get('message')}")
        except Exception as e:
            self._record(f"TSA error: {e}")

        # Fallback: local timestamp
        local_ts = {
            "type": "local_timestamp",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "manifest_sha256": manifest_sha256,
            "note": "TSA unavailable, local timestamp only",
        }
        local_path = self._output_dir / "manifest_timestamp.json"
        with open(local_path, "w", encoding="utf-8") as f:
            json.dump(local_ts, f, indent=2, ensure_ascii=False)

        self._record("Falling back to local timestamp")
        return {
            "success": True,
            "tsa_path": str(local_path),
            "timestamp": local_ts["timestamp"],
            "issuer": "Nephele Workshop (local)",
            "local_only": True,
        }

    # ===== Step 9: Save operation log =====

    def save_log(self) -> str:
        """Write the operation log to file."""
        log_path = self._output_dir / "operation_log.txt"
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("Nephele Workshop - URL Evidence Capture Log\n")
            f.write(f"Evidence ID: {self._evidence_id}\n")
            f.write("=" * 60 + "\n\n")
            for entry in self._log:
                f.write(entry + "\n")
        return str(log_path)

    # ===== Orchestrator =====

    def capture(
        self,
        url: str,
        progress_callback=None,
    ) -> Dict:
        """
        Execute the full URL evidence capture pipeline.

        Args:
            url: Target URL to capture
            progress_callback: Optional (step, total, message) callback

        Returns:
            {
                "success": bool,
                "evidence_id": str,
                "output_dir": str,
                "manifest": dict,
                "timestamp_info": dict,
                "message": str,
            }
        """
        total_phases = 5
        self._record(f"Starting evidence capture for: {url}")

        try:
            # Phase 1: Environment + DNS + TLS certificate
            if progress_callback:
                progress_callback(1, total_phases, "Collecting environment info...")
            environment = self.collect_environment()
            dns_info = self.resolve_dns(url)
            tls_info = self.capture_tls_certificate(url)

            # Phase 2: Browser capture (navigate + screenshot + HTML + images)
            if progress_callback:
                progress_callback(2, total_phases, "Capturing page...")
            artifacts = self.capture_page(url, progress_callback=None)

            # Phase 3: Hash all artifacts (including TLS cert files)
            if progress_callback:
                progress_callback(3, total_phases, "Computing hashes...")
            file_hashes = self.hash_artifacts(artifacts)

            # Also hash TLS cert + response headers files
            for extra_key in ("der_path", "pem_path"):
                p = Path(tls_info.get(extra_key, ""))
                if p.exists():
                    file_hashes[p.name] = {
                        "sha256": self._sha256_file(p),
                        "size": p.stat().st_size,
                        "type": "tls_certificate",
                    }
            resp_headers_path = artifacts.get("response_headers_path")
            if resp_headers_path and Path(resp_headers_path).exists():
                p = Path(resp_headers_path)
                file_hashes[p.name] = {
                    "sha256": self._sha256_file(p),
                    "size": p.stat().st_size,
                    "type": "response_headers",
                }

            # Phase 4: Generate manifest (save log first so it's included)
            log_path = Path(self.save_log())
            self._log_committed = True  # Log content is now frozen for hashing
            file_hashes[log_path.name] = {
                "sha256": self._sha256_file(log_path),
                "size": log_path.stat().st_size,
                "type": "operation_log",
            }

            if progress_callback:
                progress_callback(4, total_phases, "Generating manifest...")
            manifest = self.generate_manifest(
                target_url=url,
                environment=environment,
                dns_info=dns_info,
                artifacts=artifacts,
                file_hashes=file_hashes,
                tls_info=tls_info,
            )

            # Phase 5: Timestamp
            if progress_callback:
                progress_callback(5, total_phases, "Requesting timestamp...")
            ts_info = self.timestamp_manifest(manifest)

            # DO NOT re-save operation log — the version already hashed in manifest
            # is the authoritative one. Any further _record() calls only live in memory.

            image_count = len(artifacts.get("images", []))

            # Phase 6: Package as .nep (tamper-proof archive)
            # Uses files on disk (which match manifest hashes)
            nep_path = self._package_nep()

            return {
                "success": True,
                "evidence_id": self._evidence_id,
                "output_dir": str(self._output_dir),
                "nep_path": str(nep_path),
                "manifest": manifest,
                "timestamp_info": ts_info,
                "page_title": artifacts.get("page_title", ""),
                "image_count": image_count,
                "file_count": len(file_hashes),
                "message": (
                    f"URL evidence captured: {len(file_hashes)} files, "
                    f"{image_count} images, timestamp by {ts_info.get('issuer', 'N/A')}"
                ),
            }

        except URLEvidenceError as e:
            self._record(f"FATAL: {e}")
            if not self._log_committed:
                self.save_log()
            return {
                "success": False,
                "evidence_id": self._evidence_id,
                "output_dir": str(self._output_dir),
                "message": str(e),
            }
        except Exception as e:
            self._record(f"UNEXPECTED ERROR: {e}")
            if not self._log_committed:
                self.save_log()
            logger.exception("URL evidence capture failed")
            return {
                "success": False,
                "evidence_id": self._evidence_id,
                "output_dir": str(self._output_dir),
                "message": f"Unexpected error: {e}",
            }

    # ===== Helpers =====

    def _package_nep(self) -> Path:
        """
        Package the entire evidence directory as a .nep file.
        .nep = ZIP with all evidence artifacts, used as a single tamper-proof archive.
        Users interact with this one file; verification tools unpack and validate.
        """
        import zipfile

        nep_path = self._output_dir.parent / f"{self._output_dir.name}.nep"

        with zipfile.ZipFile(nep_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for item in sorted(self._output_dir.rglob("*")):
                if item.is_file():
                    arcname = item.relative_to(self._output_dir).as_posix()
                    zf.write(item, arcname)

        return nep_path

    @staticmethod
    def _sha256_file(path: Path) -> str:
        sha = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha.update(chunk)
        return sha.hexdigest()


# ===== Convenience function =====

def capture_url_evidence(
    url: str,
    output_dir: Optional[Path] = None,
    tsa_provider: str = "digicert",
    tsa_timeout: int = 30,
    progress_callback=None,
) -> Dict:
    """
    One-call convenience function for URL evidence capture.

    Args:
        url: Target URL
        output_dir: Output directory (auto-generated if None)
        tsa_provider: TSA provider name
        tsa_timeout: TSA timeout in seconds
        progress_callback: Optional (step, total, message) callback

    Returns:
        Result dict with success, evidence_id, output_dir, manifest, etc.
    """
    if output_dir is None:
        from urllib.parse import urlparse
        parsed = urlparse(url if "://" in url else f"https://{url}")
        hostname = (parsed.hostname or "unknown").replace(".", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = Path.home() / ".nephele_workshop" / "url_evidence"
        output_dir = base / f"{ts}_{hostname}"

    capture = URLEvidenceCapture(
        output_dir=output_dir,
        tsa_provider=tsa_provider,
        tsa_timeout=tsa_timeout,
    )
    return capture.capture(url, progress_callback=progress_callback)
