"""
Browser Session Manager - Playwright 生命周期管理。
单例模式，懒初始化，整个应用共享一个 browser 实例。
"""
import asyncio
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

# Playwright 是否可用的标志
_playwright_available: Optional[bool] = None

# playwright-stealth 是否可用
_stealth_available: Optional[bool] = None


async def _apply_stealth(page) -> bool:
    """Apply playwright-stealth anti-detection patches to a Page.

    playwright-stealth>=2 dropped the top-level ``stealth_async`` helper in
    favour of a ``Stealth`` class with ``apply_stealth_async``. Keep a
    fallback for the legacy API so bumping either direction doesn't silently
    disable bot evasion — Pinterest/Huaban immediately start serving empty
    or login-wall pages to an un-patched headless Chromium.
    """
    global _stealth_available
    try:
        from playwright_stealth import Stealth  # new API (>=2.x)
        await Stealth().apply_stealth_async(page)
        _stealth_available = True
        return True
    except (ImportError, AttributeError):
        pass
    try:
        from playwright_stealth import stealth_async  # legacy API (1.x)
        await stealth_async(page)
        _stealth_available = True
        return True
    except ImportError:
        pass
    if _stealth_available is None:
        logger.warning(
            "[Browser] playwright-stealth not usable (neither Stealth nor "
            "stealth_async exported) — headless sites may serve login walls"
        )
    _stealth_available = False
    return False


def _check_stealth_available() -> bool:
    """Probe whether playwright-stealth is importable with a known API.

    Kept for the existing call sites; actual patching uses _apply_stealth.
    """
    global _stealth_available
    if _stealth_available is not None:
        return _stealth_available
    try:
        from playwright_stealth import Stealth  # noqa: F401
        _stealth_available = True
        return True
    except ImportError:
        pass
    try:
        from playwright_stealth import stealth_async  # noqa: F401
        _stealth_available = True
        return True
    except ImportError:
        _stealth_available = False
        logger.debug("[Browser] playwright-stealth 未安装，跳过反检测")
    return _stealth_available


# ==================== 路由拦截规则 ====================
# 广告/追踪/分析域名（按字母排序，便于维护）
_BLOCKED_DOMAINS = (
    "adservice.google.com",
    "analytics.google.com",
    "cdn.mxpnl.com",           # Mixpanel
    "connect.facebook.net",
    "doubleclick.net",
    "google-analytics.com",
    "googleadservices.com",
    "googlesyndication.com",
    "googletagmanager.com",
    "hotjar.com",
    "mc.yandex.ru",
    "platform.twitter.com/widgets.js",
    "sb.scorecardresearch.com",
    "sentry.io",
    "static.ads-twitter.com",
    "www.google-analytics.com",
)

# 浏览器加速：可安全跳过的资源类型后缀
_BLOCKED_EXTENSIONS = (
    ".woff", ".woff2", ".ttf", ".otf", ".eot",  # 字体
)


_ALLOWED_PROXY_SCHEMES = ("http://", "https://", "socks5://", "socks4://")


def _read_browser_proxy() -> Optional[dict]:
    """
    Read the user-configured browser proxy from QSettings("NepheleWorkshop", "Network").
    Returns {"server": "..."} for Playwright, or None if unset/invalid.
    Accepted: http://host:port, https://host:port, socks5://host:port, socks4://host:port.
    Optional `user:pass@` is preserved (Playwright parses it).
    """
    try:
        from PySide6.QtCore import QSettings
        s = QSettings("NepheleWorkshop", "Network")
        raw = (s.value("browser_proxy", "") or "").strip()
        if not raw:
            return None
        if not any(raw.startswith(p) for p in _ALLOWED_PROXY_SCHEMES):
            logger.warning("[Browser] Proxy scheme not supported: %s", raw)
            return None
        return {"server": raw}
    except Exception as e:
        logger.debug("[Browser] Proxy read failed: %s", e)
        return None


def check_playwright_available() -> bool:
    """检查 Playwright 是否已安装。成功后缓存，失败则每次重试。"""
    global _playwright_available
    if _playwright_available is True:
        return True
    try:
        import playwright  # noqa: F401
        _playwright_available = True
    except ImportError:
        _playwright_available = False
        logger.warning("[Browser] Playwright 未安装，浏览器功能不可用")
    return _playwright_available


class BrowserManager:
    """
    浏览器管理器（单例）。
    管理 Playwright Chromium 实例的完整生命周期。
    """

    _instance: Optional["BrowserManager"] = None

    @classmethod
    def instance(cls) -> "BrowserManager":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._playwright = None
        self._browser = None
        self._context = None
        self._page = None
        self._headless = True
        self._mode = "headless"  # "headless" | "user"
        self._chrome_process = None  # CDP mode: the Chrome process we launched
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        # ref 映射：snapshot 生成的 ref_id → {role, name, nth}
        self._ref_map: dict = {}
        # 响应拦截缓存：url → bytes（页面加载期间拦截的图片响应体）
        self._image_response_cache: dict = {}
        # 上次 extract_images 的结果（供 show_reference_picker 直接读取，避免 LLM 编造 URL）
        self._last_extracted_images: list = []

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        """获取或创建 event loop（兼容 QThread 环境）"""
        if self._loop is None or self._loop.is_closed():
            self._loop = asyncio.new_event_loop()
        return self._loop

    def _run(self, coro):
        """在 event loop 中运行协程（同步包装，供 Agent Tool 调用）"""
        loop = self._get_loop()
        return loop.run_until_complete(coro)

    # ========== 生命周期 ==========

    def ensure_browser(self, headless: bool = True) -> bool:
        """
        确保浏览器已启动。懒初始化。
        Returns: True 如果成功，False 如果 Playwright 不可用。
        """
        if not check_playwright_available():
            return False

        if self._browser and self._browser.is_connected():
            # 如果 headless 模式改变，需要重启
            if headless != self._headless:
                self.close()
            else:
                return True

        # 打包模式：让 Playwright 在 driver/package/.local-browsers/ 下找浏览器
        # CI 构建时 PLAYWRIGHT_BROWSERS_PATH=0 会把 Chromium 装到这里
        # 开发环境不设此变量时 Playwright 用默认路径 (%LOCALAPPDATA%\ms-playwright)
        if not os.environ.get("PLAYWRIGHT_BROWSERS_PATH"):
            import sys
            # 检测打包模式：Nuitka 编译后 sys.executable 指向 .exe 而非 python.exe
            exe_name = os.path.basename(sys.executable).lower()
            if not exe_name.startswith("python"):
                os.environ["PLAYWRIGHT_BROWSERS_PATH"] = "0"
                logger.debug("[Browser] 打包模式，设置 PLAYWRIGHT_BROWSERS_PATH=0")

        self._headless = headless
        try:
            return self._run(self._async_launch(headless))
        except Exception as e:
            logger.error("[Browser] 启动失败: %s", e, exc_info=True)
            return False

    async def _async_launch(self, headless: bool) -> bool:
        """异步启动 Playwright + Chromium"""
        from playwright.async_api import async_playwright

        logger.info("[Browser] 启动 Chromium (headless=%s)", headless)

        self._playwright = await async_playwright().start()

        launch_args = {
            "headless": headless,
            "args": [
                "--disable-blink-features=AutomationControlled",
                "--no-first-run",
                "--disable-default-apps",
                # QUIC/UDP often fails under VPN TUN mode; force HTTPS over TCP.
                "--disable-quic",
            ]
        }

        # User-configured HTTP/SOCKS proxy — more reliable than relying on
        # the OS-level VPN TUN (which may leak IPv6, block UDP, or miss DNS).
        proxy_cfg = _read_browser_proxy()
        if proxy_cfg:
            launch_args["proxy"] = proxy_cfg
            logger.info("[Browser] Using proxy: %s", proxy_cfg["server"])

        self._browser = await self._playwright.chromium.launch(**launch_args)
        self._context = await self._browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            locale="zh-CN",
            # 禁止 Service Worker 缓存，确保图片响应拦截完整生效
            service_workers="block",
        )

        # 路由拦截：屏蔽广告/追踪 + 跳过字体加载（加速页面加载）
        await self._setup_route_blocking()

        self._page = await self._context.new_page()

        # 注册响应拦截器：自动缓存图片响应体（绕过 CDN 防盗链）
        self._page.on("response", self._on_page_response)

        # 反检测：playwright-stealth 补丁（隐藏自动化特征）
        if await _apply_stealth(self._page):
            logger.info("[Browser] Stealth 反检测补丁已应用")

        logger.info("[Browser] Chromium 已启动")
        return True

    # ========== User Browser Mode (Persistent Profile + CDP) ==========
    # Pattern from browser-use: dedicated debug profile, cookies persist across
    # sessions. User logs in once, Nephele remembers. No conflict with user's
    # main Chrome — separate profile directory.

    CDP_PORT = 9242  # 9242 like browser-use, avoids conflict with devtools on 9222
    # Additional CDP ports to probe before launching fresh Chrome. Our
    # probe_bilibili.py uses 9243 — if the user just ran it, the Chrome
    # instance is still holding the profile and no new one can launch
    # against the same profile dir. Reusing that session is strictly better
    # than failing.
    _FALLBACK_CDP_PORTS = (9243,)
    _USER_PROFILE_DIR = os.path.join(
        os.path.expanduser("~"), ".nephele_workshop", "chrome_profile",
    )

    def ensure_user_browser(self) -> bool:
        """Launch Chrome with Nephele's persistent profile (cookies saved).

        First time: fresh browser, user logs in manually → cookies persist.
        Subsequent times: cookies are already there from previous sessions.
        Does NOT touch the user's main Chrome profile — zero conflict.
        """
        if not check_playwright_available():
            return False

        if self._browser and self._browser.is_connected() and self._mode == "user":
            return True

        if self._browser:
            self.close()

        self._mode = "user"
        self._headless = False
        try:
            return self._run(self._async_connect_user_browser())
        except Exception as e:
            logger.error("[Browser] User browser failed: %s", e, exc_info=True)
            self._mode = "headless"
            return False

    async def _async_connect_user_browser(self) -> bool:
        """Launch Chrome with dedicated profile + CDP, then connect."""
        import subprocess as _sp

        cdp_url = f"http://localhost:{self.CDP_PORT}"

        # Check if already running from a previous session
        if await self._probe_cdp(cdp_url):
            logger.info("[Browser] CDP already available at %s", cdp_url)
        elif await self._try_fallback_cdp():
            cdp_url = self._fallback_cdp_url  # set by _try_fallback_cdp
        else:
            chrome_path = self._find_chrome_exe()
            if not chrome_path:
                raise RuntimeError(
                    "未找到 Chrome 或 Edge 浏览器。请确认已安装其中之一。"
                )

            os.makedirs(self._USER_PROFILE_DIR, exist_ok=True)
            logger.info("[Browser] Launching Chrome: %s", chrome_path)
            logger.info("[Browser] Nephele profile: %s", self._USER_PROFILE_DIR)

            self._chrome_process = _sp.Popen(
                [
                    chrome_path,
                    f"--remote-debugging-port={self.CDP_PORT}",
                    f"--remote-allow-origins=*",
                    f"--user-data-dir={self._USER_PROFILE_DIR}",
                    "--disable-features=DevToolsDebuggingRestrictions",
                    "--no-first-run",
                    "--no-default-browser-check",
                ],
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
            )

            # Wait for CDP (up to 8 seconds — first launch with fresh profile is slow)
            import asyncio
            for _ in range(80):
                if await self._probe_cdp(cdp_url):
                    break
                await asyncio.sleep(0.1)
            else:
                raise RuntimeError(
                    "Chrome 启动超时。请检查是否有其他程序占用了端口 "
                    f"{self.CDP_PORT}，或尝试手动关闭所有 Chrome 窗口后重试。"
                )

        # Connect via Playwright CDP
        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.connect_over_cdp(cdp_url)
        logger.info("[Browser] CDP connected to %s", cdp_url)

        # Use the default context (Nephele profile with persistent cookies)
        contexts = self._browser.contexts
        if contexts:
            self._context = contexts[0]
        else:
            self._context = await self._browser.new_context()

        self._page = await self._context.new_page()
        self._page.on("response", self._on_page_response)

        await _apply_stealth(self._page)

        logger.info("[Browser] User browser ready (persistent profile, cookies active)")
        return True

    async def _try_fallback_cdp(self) -> bool:
        """Probe known fallback ports. Set self._fallback_cdp_url on hit."""
        for port in self._FALLBACK_CDP_PORTS:
            url = f"http://localhost:{port}"
            if await self._probe_cdp(url):
                logger.info("[Browser] Reusing Chrome on fallback CDP port %d", port)
                self._fallback_cdp_url = url
                return True
        self._fallback_cdp_url = ""
        return False

    @staticmethod
    async def _probe_cdp(cdp_url: str) -> bool:
        """Check if CDP endpoint is responding."""
        import asyncio
        try:
            import urllib.request
            req = urllib.request.Request(f"{cdp_url}/json/version", method="GET")
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(
                None,
                lambda: urllib.request.urlopen(req, timeout=1),
            )
            return resp.status == 200
        except Exception:
            return False

    @staticmethod
    def _find_chrome_exe() -> Optional[str]:
        """Find Chrome or Edge executable on Windows."""
        candidates = []
        for env_var in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            base = os.environ.get(env_var, "")
            if not base:
                continue
            candidates.extend([
                os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"),
                os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
            ])
        for path in candidates:
            if os.path.isfile(path):
                return path
        return None

    @property
    def is_user_browser(self) -> bool:
        """Whether currently connected in user browser mode."""
        return self._mode == "user" and self._browser is not None and self._browser.is_connected()

    async def _setup_route_blocking(self) -> None:
        """设置路由拦截规则：屏蔽广告/追踪脚本 + 不必要的字体加载。"""

        async def _block_handler(route):
            await route.abort()

        # 1. 按域名屏蔽广告/追踪
        for domain in _BLOCKED_DOMAINS:
            await self._context.route(f"**/{domain}/**", _block_handler)

        # 2. 按扩展名跳过字体（艺术网站加载自定义字体很慢，对图片提取无用）
        for ext in _BLOCKED_EXTENSIONS:
            await self._context.route(f"**/*{ext}", _block_handler)

        logger.debug("[Browser] 路由拦截规则已设置 (%d 域名, %d 扩展名)",
                     len(_BLOCKED_DOMAINS), len(_BLOCKED_EXTENSIONS))

    def _on_page_response(self, response) -> None:
        """同步响应事件处理器 — 将异步缓存任务调度到事件循环。"""
        try:
            # 快速过滤：只处理成功的图片响应
            if response.status != 200:
                return

            content_type = response.headers.get("content-type", "")
            is_image = "image/" in content_type

            if not is_image:
                url_lower = response.url.lower().split("?")[0]
                is_image = any(
                    url_lower.endswith(ext)
                    for ext in (".jpg", ".jpeg", ".png", ".webp", ".gif", ".avif")
                )

            if not is_image:
                return

            # 限制缓存条目数
            if len(self._image_response_cache) >= 80:
                return

            # 调度异步任务读取响应体（不阻塞页面加载）
            loop = self._get_loop()
            if loop.is_running():
                loop.create_task(self._cache_response_body(response))
        except Exception:
            pass

    async def _cache_response_body(self, response) -> None:
        """异步读取并缓存图片响应体。

        关键：遍历整个重定向链，将 body 缓存到所有 URL 下。
        例如 Behance CDN 重定向:
          mir-s3-cdn-cf.behance.net/projects/404/xxx.png  (原始 URL, extract_images 返回)
          → 301 →
          mir-cdn.behance.net/v1/rendition/projects/404/xxx.png  (最终 URL, 响应实际来源)
        需要在两个 URL 下都缓存，否则 download_images_to_cache 用原始 URL 查找不到。
        """
        try:
            body = await response.body()
            if not body:
                return

            size = len(body)
            # 跳过太小（图标）或太大（>10MB）的图片
            if size < 2000 or size > 10 * 1024 * 1024:
                return

            # 1. 缓存到最终响应 URL
            self._image_response_cache[response.url] = body

            # 2. 遍历重定向链，缓存到所有前序 URL（含原始请求 URL）
            #    response.request.redirected_from 返回重定向链的上一个 Request
            cached_url_count = 1  # 已缓存 response.url
            try:
                req = response.request
                seen = {response.url}
                while req:
                    if req.url not in seen:
                        self._image_response_cache[req.url] = body
                        seen.add(req.url)
                        cached_url_count += 1
                    redirected_from = req.redirected_from
                    if redirected_from is None:
                        break
                    req = redirected_from
            except Exception:
                pass

            logger.debug(
                "[Browser] 拦截缓存图片: %s (%d KB, %d URLs)",
                response.url[:80], size // 1024, cached_url_count,
            )
        except Exception:
            pass  # 不让缓存异常影响页面加载

    def close(self):
        """关闭浏览器，释放资源。应用退出前必须调用。"""
        if self._browser or self._playwright:
            try:
                self._run(self._async_close())
            except Exception as e:
                logger.debug("[Browser] 异步关闭失败，尝试强制清理: %s", e)
                self._browser = None
                self._context = None
                self._page = None
                if self._playwright:
                    try:
                        self._run(self._playwright.stop())
                    except Exception:
                        pass
                    self._playwright = None
        # CDP mode: do NOT kill the user's Chrome — just disconnect.
        # The user may have other tabs open. We only terminate if WE launched it
        # and it has no other pages.
        self._chrome_process = None
        # 关闭 event loop，防止 "Task was destroyed but is pending" 警告
        if self._loop and not self._loop.is_closed():
            try:
                self._loop.close()
            except Exception:
                pass
            self._loop = None
        self._ref_map = {}
        self._image_response_cache.clear()
        self._mode = "headless"

    async def _async_close(self):
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None
        self._context = None
        self._page = None
        logger.info("[Browser] 已关闭")

    # ========== 页面操作 ==========

    def navigate(self, url: str, wait_until: str = "domcontentloaded",
                 timeout_ms: int = 30000) -> dict:
        """导航到 URL

        Args:
            url: 目标 URL
            wait_until: 等待策略 (domcontentloaded / load / networkidle)
            timeout_ms: 超时毫秒数，默认 30000 (30秒)
        """
        if not self.ensure_browser(self._headless):
            return {"success": False, "message": "浏览器不可用，请检查 Playwright 安装"}
        try:
            result = self._run(self._async_navigate(url, wait_until, timeout_ms))
            return result
        except Exception as e:
            return {"success": False, "message": f"导航失败: {e}"}

    def wait_for_load_state(self, state: str = "load", timeout_ms: int = 5000) -> dict:
        """Wait for a Playwright load state, swallowing timeouts.

        Called between ``scroll`` and ``extract_images`` on infinite-scroll
        pages (Pinterest / Huaban) so lazy-loaded <img> tags have a chance
        to paint before we snapshot the DOM. ``networkidle`` never fires on
        infinite-scroll pages — use ``"load"`` which triggers once the
        initial viewport's resources finish.
        """
        if not self._page:
            return {"success": False, "message": "No page"}
        try:
            self._run(self._async_wait_for_load_state(state, timeout_ms))
            return {"success": True}
        except Exception as e:
            logger.debug("[Browser] wait_for_load_state(%s) soft-fail: %s", state, e)
            return {"success": False, "message": str(e)}

    async def _async_wait_for_load_state(self, state: str, timeout_ms: int) -> None:
        await self._page.wait_for_load_state(state, timeout=timeout_ms)

    async def _async_navigate(self, url: str, wait_until: str,
                              timeout_ms: int = 30000) -> dict:
        # 自动补全 scheme
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        # 新页面导航前清空图片响应缓存
        self._image_response_cache.clear()

        await self._page.goto(url, wait_until=wait_until, timeout=timeout_ms)
        # 等待一下让响应拦截任务有机会完成
        await asyncio.sleep(0.3)
        title = await self._page.title()
        final_url = self._page.url
        self._ref_map = {}  # 导航后清空 ref（ref 不跨页面）

        # 检测登录墙（三层检测）
        is_login_page = False

        # Layer 1: URL 重定向检测（如 B 站跳转到 passport.bilibili.com）
        login_url_patterns = [
            "passport.bilibili.com", "accounts.google.com",
            "login.microsoftonline.com", "id.apple.com",
            "/login", "/signin", "/sign-in", "/passport",
            "/auth/login", "/oauth/authorize",
        ]
        url_lower = final_url.lower()
        is_login_page = any(pat in url_lower for pat in login_url_patterns)

        # Layer 2: 页面标题检测
        if not is_login_page and title:
            login_titles = ["出错啦", "登录", "login", "sign in", "log in"]
            is_login_page = any(t in title.lower() for t in login_titles)

        # Layer 3: 弹窗式登录墙检测（URL/title 正常但内容被遮挡）
        # 例如 ArtStation 弹窗登录：URL 不变，但页面内容只有登录表单
        if not is_login_page:
            try:
                has_login_wall = await self._page.evaluate("""
                    () => {
                        const body = document.body;
                        if (!body) return false;
                        // 方法1: 可见的密码输入框
                        const pwdInputs = body.querySelectorAll(
                            'input[type="password"]'
                        );
                        for (const inp of pwdInputs) {
                            const rect = inp.getBoundingClientRect();
                            if (rect.width > 0 && rect.height > 0) return true;
                        }
                        // 方法2: 存在密码输入框 + 页面文本包含登录关键词
                        if (pwdInputs.length > 0) {
                            const text = body.innerText.toLowerCase();
                            const hasSignIn = text.includes('sign in') || text.includes('登录');
                            const hasSignUp = text.includes('sign up') || text.includes('注册');
                            if (hasSignIn && hasSignUp) return true;
                        }
                        return false;
                    }
                """)
                is_login_page = bool(has_login_wall)
                if is_login_page:
                    logger.info("[Browser] 检测到弹窗式登录墙: %s", final_url)
            except Exception:
                pass  # JS 执行失败不影响正常导航

        if is_login_page:
            msg = (f"已导航到: {title} (需要登录！浏览器无登录态，"
                   f"建议改用公开API或询问用户获取具体信息)")
            return {"success": True, "message": msg, "title": title,
                    "url": final_url, "login_required": True}

        return {"success": True, "message": f"已导航到: {title}",
                "title": title, "url": final_url}

    def snapshot(self, interactive_only: bool = False) -> dict:
        """生成页面 Semantic Snapshot"""
        if not self._page:
            return {"success": False, "message": "浏览器未打开"}
        try:
            return self._run(self._async_snapshot(interactive_only))
        except Exception as e:
            return {"success": False, "message": f"快照失败: {e}"}

    async def _async_snapshot(self, interactive_only: bool) -> dict:
        from core.browser.snapshot import semantic_snapshot
        snapshot_text, ref_map = await semantic_snapshot(self._page, interactive_only)
        self._ref_map = ref_map
        return {
            "success": True,
            "message": snapshot_text,
            "ref_count": len(ref_map),
        }

    def snapshot_annotated(self) -> dict:
        """Stagehand-style annotated screenshot with labeled interactive elements."""
        if not self._page:
            return {"success": False, "message": "浏览器未打开"}
        try:
            return self._run(self._async_snapshot_annotated())
        except Exception as e:
            return {"success": False, "message": f"标注截图失败: {e}"}

    async def _async_snapshot_annotated(self) -> dict:
        from core.browser.snapshot import annotated_screenshot
        snapshot_text, ref_map, screenshot_path = await annotated_screenshot(self._page)
        self._ref_map = ref_map
        return {
            "success": True,
            "message": snapshot_text,
            "ref_count": len(ref_map),
            "output_path": screenshot_path,
        }

    def click(self, ref_id: str) -> dict:
        """通过 ref ID 点击元素"""
        if not self._page:
            return {"success": False, "message": "浏览器未打开"}
        if ref_id not in self._ref_map:
            return {"success": False, "message": f"ref {ref_id} 不存在，请先执行 snapshot"}
        try:
            return self._run(self._async_click(ref_id))
        except Exception as e:
            return {"success": False, "message": f"点击失败: {e}"}

    async def _async_click(self, ref_id: str) -> dict:
        from core.browser.snapshot import resolve_ref
        locator = await resolve_ref(self._page, self._ref_map, ref_id)
        await locator.click(timeout=10000)
        # 点击后等待一下可能的页面变化
        await self._page.wait_for_load_state("domcontentloaded", timeout=5000)
        self._ref_map = {}  # 点击可能导致页面变化，清空 ref
        return {"success": True, "message": f"已点击 {ref_id}"}

    def type_text(self, ref_id: str, text: str) -> dict:
        """在指定元素中输入文本"""
        if not self._page:
            return {"success": False, "message": "浏览器未打开"}
        if ref_id not in self._ref_map:
            return {"success": False, "message": f"ref {ref_id} 不存在"}
        try:
            return self._run(self._async_type(ref_id, text))
        except Exception as e:
            return {"success": False, "message": f"输入失败: {e}"}

    async def _async_type(self, ref_id: str, text: str) -> dict:
        from core.browser.snapshot import resolve_ref
        locator = await resolve_ref(self._page, self._ref_map, ref_id)
        await locator.fill(text, timeout=10000)
        return {"success": True, "message": f"已在 {ref_id} 输入文本"}

    def scroll(self, direction: str = "down", amount: int = 3) -> dict:
        """滚动页面"""
        if not self._page:
            return {"success": False, "message": "浏览器未打开"}
        try:
            return self._run(self._async_scroll(direction, amount))
        except Exception as e:
            return {"success": False, "message": f"滚动失败: {e}"}

    async def _async_scroll(self, direction: str, amount: int) -> dict:
        delta = -500 * amount if direction == "up" else 500 * amount
        await self._page.mouse.wheel(0, delta)
        # 等待懒加载内容（也让响应拦截器有时间缓存新加载的图片）
        await asyncio.sleep(1.5)
        self._ref_map = {}  # 滚动可能加载新内容
        return {"success": True, "message": f"已向{'上' if direction == 'up' else '下'}滚动"}

    def press_key(self, key: str) -> dict:
        """按键（如 Enter, Escape, Tab）"""
        if not self._page:
            return {"success": False, "message": "浏览器未打开"}
        try:
            return self._run(self._async_press(key))
        except Exception as e:
            return {"success": False, "message": f"按键失败: {e}"}

    async def _async_press(self, key: str) -> dict:
        await self._page.keyboard.press(key)
        await asyncio.sleep(0.5)
        return {"success": True, "message": f"已按下 {key}"}

    def extract_images(self, min_size: int = 200) -> dict:
        """提取页面中的图片 URL 列表（过滤小图标）"""
        if not self._page:
            return {"success": False, "message": "浏览器未打开"}
        try:
            return self._run(self._async_extract_images(min_size))
        except Exception as e:
            return {"success": False, "message": f"提取图片失败: {e}"}

    async def _async_extract_images(self, min_size: int) -> dict:
        """提取页面图片，过滤 min_size 以下的小图。
        支持 srcset、data-src 等懒加载属性，自动选取最大尺寸。
        """
        images = await self._page.evaluate("""
            (minSize) => {
                /**
                 * 从 srcset 中挑最大的 URL
                 * srcset 格式: "url1 236w, url2 564w, url3 736w"
                 */
                function bestFromSrcset(srcset) {
                    if (!srcset) return null;
                    let best = null, bestW = 0;
                    for (const entry of srcset.split(',')) {
                        const parts = entry.trim().split(/\\s+/);
                        if (parts.length < 1) continue;
                        const url = parts[0];
                        let w = 0;
                        if (parts.length > 1) {
                            const m = parts[1].match(/(\\d+)/);
                            if (m) w = parseInt(m[1], 10);
                        }
                        if (!best || w > bestW) { best = url; bestW = w; }
                    }
                    return best;
                }

                const results = [];
                const imgs = document.querySelectorAll('img');

                for (const img of imgs) {
                    // 1. 优先 srcset 最大版本
                    let src = bestFromSrcset(img.getAttribute('srcset'));
                    // 2. 回退: data-src / data-pin-media / data-original (懒加载)
                    if (!src) src = img.getAttribute('data-src')
                                  || img.getAttribute('data-pin-media')
                                  || img.getAttribute('data-original');
                    // 3. 最终回退: img.src
                    if (!src) src = img.src;

                    if (!src || src.startsWith('data:') || src.startsWith('blob:')) continue;

                    const w = img.naturalWidth || img.width || 0;
                    const h = img.naturalHeight || img.height || 0;
                    if (w > 0 && h > 0) {
                        // 过滤小图 (两个维度都小于 minSize)
                        if (w < minSize && h < minSize) continue;
                        // 过滤装饰元素 (任一维度 < 50px，如分隔线、横幅边框)
                        if (w < 50 || h < 50) continue;
                        // 过滤极端宽高比 (> 5:1，如 footer banner 1800×4)
                        const ratio = w / h;
                        if (ratio > 5 || ratio < 0.2) continue;
                    }

                    results.push({
                        src: src,
                        alt: img.alt || '',
                        width: w,
                        height: h
                    });
                }
                return results;
            }
        """, min_size)

        # 去重 + CDN URL 升级（缩略图 → 大图）
        seen = set()
        unique = []
        for img in images:
            src = img["src"]
            # Pinterest CDN: /236x/ → /736x/ (升级缩略图到大图)
            if "pinimg.com" in src:
                for small in ("/236x/", "/170x/", "/150x/"):
                    if small in src:
                        src = src.replace(small, "/736x/")
                        break
            # Behance CDN: /projects/404/ → /projects/1400/ (升级项目封面缩略图)
            elif "behance.net" in src:
                for small in ("/projects/404/", "/projects/202/"):
                    if small in src:
                        src = src.replace(small, "/projects/1400/")
                        break
            img["src"] = src
            if src not in seen:
                seen.add(src)
                unique.append(img)

        # 存储提取结果（供 show_reference_picker 直接读取，避免 LLM 编造 URL）
        self._last_extracted_images = unique[:50]

        # Diagnostic: when a site returns 0 images it's useful to know
        # whether extract saw zero <img> in the DOM (reverse proxy / login
        # wall / JS-failed) vs saw many but all got filtered (min_size
        # too strict / wrong lazy-load attributes).
        logger.info(
            "[Browser] extract_images: raw=%d filtered_unique=%d min_size=%d",
            len(images), len(unique), min_size,
        )

        # When raw==0, dump page title + first 300 chars of body text so we
        # can tell login-wall / consent-page / anti-bot page from a genuine
        # "no images" result without re-running the crawl.
        if len(images) == 0:
            try:
                probe = await self._page.evaluate("""() => ({
                    title: document.title || '',
                    url: location.href,
                    bodyLen: (document.body && document.body.innerText || '').length,
                    bodyHead: (document.body && document.body.innerText || '').slice(0, 300),
                })""")
                logger.info(
                    "[Browser] extract_images raw=0 diag: url=%s title=%r bodyLen=%d head=%r",
                    probe.get("url"), probe.get("title"),
                    probe.get("bodyLen", 0), probe.get("bodyHead", ""),
                )
            except Exception as e:  # noqa: BLE001
                logger.warning("[Browser] raw=0 diagnostic failed: %s", e)

        return {
            "success": True,
            "message": f"找到 {len(unique)} 张图片",
            "data": {"images": unique[:50], "raw_count": len(images)},
        }

    def download_images_to_cache(self, urls: list) -> dict:
        """使用浏览器上下文下载图片到本地缓存（绕过防盗链）"""
        if not self._page:
            return {"success": False, "cached": {}}
        try:
            return self._run(self._async_download_images_to_cache(urls))
        except Exception as e:
            logger.error("[Browser] 下载图片到缓存失败: %s", e)
            return {"success": False, "cached": {}}

    async def _async_download_images_to_cache(self, urls: list) -> dict:
        """下载图片到本地缓存。三级回退：磁盘缓存 → 响应拦截缓存 → page.request.get()"""
        import hashlib
        from pathlib import Path

        cache_dir = Path.home() / ".nephele_workshop" / "cache" / "refs"
        cache_dir.mkdir(parents=True, exist_ok=True)

        cached = {}  # url → local_path
        from_intercept = 0
        from_request = 0

        for url in urls[:30]:  # 最多缓存 30 张
            try:
                url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
                # 从 URL 推断扩展名
                ext = ".jpg"
                for e in (".png", ".jpg", ".jpeg", ".webp", ".gif", ".avif"):
                    if e in url.lower():
                        ext = e
                        break

                local_path = cache_dir / f"{url_hash}{ext}"

                # Level 1: 磁盘缓存命中
                if local_path.exists() and local_path.stat().st_size > 0:
                    cached[url] = str(local_path)
                    continue

                body = None

                # Level 2: 响应拦截缓存（页面加载期间拦截的图片响应体）
                body = self._image_response_cache.get(url)

                # Level 2a: Pinterest URL 降级匹配（/736x/ → /236x/ 等）
                if not body and "pinimg.com" in url and "/736x/" in url:
                    for small in ("/236x/", "/564x/", "/474x/"):
                        alt_url = url.replace("/736x/", small)
                        body = self._image_response_cache.get(alt_url)
                        if body:
                            break

                # Level 2b: 文件名模糊匹配（应对 CDN 重定向导致域名不同的情况）
                # 例: extract 返回 mir-s3-cdn-cf.behance.net/projects/404/xxx.png
                #      缓存中是 mir-cdn.behance.net/v1/rendition/projects/404/xxx.png
                # 注意: 跳过已升级分辨率的 URL，避免匹配到低分辨率缓存
                is_upgraded_url = (
                    ("behance.net" in url and "/projects/1400/" in url) or
                    ("pinimg.com" in url and "/736x/" in url)
                )
                if not body and self._image_response_cache and not is_upgraded_url:
                    filename = url.rsplit("/", 1)[-1].split("?")[0]
                    if filename and len(filename) > 8:  # 避免太短的文件名误匹配
                        for cached_url, cached_body in self._image_response_cache.items():
                            if cached_url.endswith("/" + filename):
                                body = cached_body
                                logger.debug(
                                    "[Browser] 文件名模糊匹配: %s → %s",
                                    filename, cached_url[:60],
                                )
                                break

                if body:
                    local_path.write_bytes(body)
                    cached[url] = str(local_path)
                    from_intercept += 1
                    logger.debug("[Browser] 从响应缓存写入: %s", local_path.name)
                    continue

                # Level 3: page.request.get()（带浏览器 cookies/referer）
                resp = await self._page.request.get(url, timeout=15000)
                if resp.ok:
                    body = await resp.body()
                    if len(body) > 50 * 1024 * 1024:  # 50MB limit
                        continue
                    local_path.write_bytes(body)
                    cached[url] = str(local_path)
                    from_request += 1
                    logger.debug("[Browser] 通过请求下载: %s → %s", url[:60], local_path.name)
            except Exception as e:
                logger.debug("[Browser] 缓存图片失败 %s: %s", url[:60], e)

        logger.info(
            "[Browser] 图片缓存完成: %d/%d (拦截=%d, 请求=%d)",
            len(cached), len(urls[:30]), from_intercept, from_request,
        )
        return {"success": True, "cached": cached}

    def get_response_cache_stats(self) -> dict:
        """返回响应拦截缓存统计信息（调试用）"""
        total_bytes = sum(len(v) for v in self._image_response_cache.values())
        return {
            "entries": len(self._image_response_cache),
            "total_mb": round(total_bytes / 1024 / 1024, 2),
        }

    def extract_text(self) -> dict:
        """提取页面主要文本内容"""
        if not self._page:
            return {"success": False, "message": "浏览器未打开"}
        try:
            return self._run(self._async_extract_text())
        except Exception as e:
            return {"success": False, "message": f"提取文本失败: {e}"}

    async def _async_extract_text(self) -> dict:
        """提取页面正文（优先 article，降级到 body）"""
        text = await self._page.evaluate("""
            () => {
                // 尝试找 article 或 main 标签
                const article = document.querySelector('article') || document.querySelector('main');
                if (article) return article.innerText;
                // 降级到 body，但排除 header/nav/footer
                const body = document.body.cloneNode(true);
                ['header', 'nav', 'footer', 'aside', 'script', 'style'].forEach(tag => {
                    body.querySelectorAll(tag).forEach(el => el.remove());
                });
                return body.innerText;
            }
        """)

        # 截断到合理长度
        if len(text) > 4000:
            text = text[:4000] + "\n...(内容已截断)"

        return {"success": True, "message": text}

    def screenshot(self, path: Optional[str] = None) -> dict:
        """截图保存"""
        if not self._page:
            return {"success": False, "message": "浏览器未打开"}
        try:
            return self._run(self._async_screenshot(path))
        except Exception as e:
            return {"success": False, "message": f"截图失败: {e}"}

    async def _async_screenshot(self, path: Optional[str]) -> dict:
        import tempfile
        if not path:
            path = os.path.join(tempfile.gettempdir(), "nephele_screenshot.png")
        await self._page.screenshot(path=path, full_page=False)
        return {"success": True, "message": f"截图已保存: {path}", "output_path": path}

    def save_pdf(self, path: Optional[str] = None, full_page: bool = True) -> dict:
        """将当前页面保存为 PDF（仅 headless Chromium 支持）。
        用途：版权侵权网页存证（全页、可搜索文本、带 URL/时间戳页眉）。
        """
        if not self._page:
            return {"success": False, "message": "浏览器未打开"}
        if not self._headless:
            return {"success": False, "message": "PDF 导出仅支持 headless 模式"}
        try:
            return self._run(self._async_save_pdf(path, full_page))
        except Exception as e:
            return {"success": False, "message": f"PDF 导出失败: {e}"}

    async def _async_save_pdf(self, path: Optional[str], full_page: bool) -> dict:
        import tempfile
        from datetime import datetime

        if not path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(tempfile.gettempdir(), f"nephele_evidence_{timestamp}.pdf")

        current_url = self._page.url
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        await self._page.pdf(
            path=path,
            format="A4",
            print_background=True,
            display_header_footer=True,
            header_template=(
                '<div style="font-size:8px; width:100%; text-align:center; '
                'color:#666; padding:5px 20px;">'
                f'<span>{current_url}</span>'
                '</div>'
            ),
            footer_template=(
                '<div style="font-size:8px; width:100%; padding:5px 20px; '
                'color:#666; display:flex; justify-content:space-between;">'
                f'<span>Nephele Workshop Evidence Capture — {now_str}</span>'
                '<span>Page <span class="pageNumber"></span> / '
                '<span class="totalPages"></span></span>'
                '</div>'
            ),
        )

        # 获取文件大小
        file_size_kb = os.path.getsize(path) // 1024

        return {
            "success": True,
            "message": f"PDF 已保存: {path} ({file_size_kb} KB)",
            "output_path": path,
            "data": {"url": current_url, "timestamp": now_str},
        }


    def create_evidence_context(self, har_path: str) -> dict:
        """
        Create a dedicated browser context with HAR recording for forensic capture.
        The context records ALL network traffic (requests + responses) to a HAR file.

        Returns:
            {"success": bool, "message": str}
        """
        if not self._browser or not self._browser.is_connected():
            if not self.ensure_browser(self._headless):
                return {"success": False, "message": "Browser unavailable"}

        try:
            result = self._run(self._async_create_evidence_context(har_path))
            return result
        except Exception as e:
            return {"success": False, "message": f"Failed to create evidence context: {e}"}

    async def _async_create_evidence_context(self, har_path: str) -> dict:
        """Create evidence context with HAR recording."""
        # Close existing context/page
        if self._page:
            await self._page.close()
        if self._context:
            await self._context.close()

        # Create new context with HAR recording
        self._context = await self._browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            locale="zh-CN",
            service_workers="block",
            record_har_path=har_path,
            record_har_content="attach",  # Embed response bodies in HAR
        )

        await self._setup_route_blocking()
        self._page = await self._context.new_page()
        self._page.on("response", self._on_page_response)

        await _apply_stealth(self._page)

        logger.info("[Browser] Evidence context created with HAR recording: %s", har_path)
        return {"success": True, "message": "Evidence context with HAR recording created"}

    def close_evidence_context(self) -> dict:
        """
        Close the evidence context, finalizing the HAR file.
        After this, the BrowserManager is in a "needs reinit" state —
        the next ensure_browser() call will create a fresh context.
        """
        try:
            self._run(self._async_close_evidence_context())
            return {"success": True, "message": "Evidence context closed, HAR saved"}
        except Exception as e:
            return {"success": False, "message": f"Failed to close evidence context: {e}"}

    async def _async_close_evidence_context(self):
        """Close the context (this triggers HAR file write)."""
        if self._page:
            await self._page.close()
            self._page = None
        if self._context:
            await self._context.close()  # This writes the HAR file
            self._context = None
        self._ref_map = {}
        self._image_response_cache.clear()
        logger.info("[Browser] Evidence context closed")


def get_browser_manager() -> BrowserManager:
    """获取 BrowserManager 单例"""
    return BrowserManager.instance()
