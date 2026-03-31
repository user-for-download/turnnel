#!/usr/bin/env python3
"""
Автоматическое получение OK auth_token со страницы VK-звонка.

Первый запуск (логин в VK, видимый браузер):
    python3 get_vk_token.py --login 'https://vk.com/call/join/...'

Последующие запуски (фоновый режим, сессия сохранена):
    python3 get_vk_token.py 'https://vk.com/call/join/...'
"""

import sys
import os
import re
import json
import argparse
import urllib.parse
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PwTimeout
except ImportError:
    print(
        "playwright not installed.\n"
        "  pip install playwright && playwright install chromium",
        file=sys.stderr,
    )
    sys.exit(1)

BROWSER_DIR = Path.home() / ".turnnel-browser"


def log(msg):
    print(f"[token] {msg}", file=sys.stderr)


def token_from_post(request):
    """Извлечь auth_token из POST к fb.do."""
    try:
        body = request.post_data
        if not body:
            return None
        # form-urlencoded: session_data=...&method=...
        parsed = urllib.parse.parse_qs(body)
        if "session_data" not in parsed:
            return None
        sd = json.loads(parsed["session_data"][0])
        tok = sd.get("auth_token", "")
        if tok.startswith("$") and len(tok) > 20:
            return tok
    except Exception:
        pass
    return None


def token_from_html(html):
    """Извлечь auth_token из HTML/JS кода страницы."""
    patterns = [
        r'"auth_token"\s*:\s*"(\$[a-zA-Z0-9_/+=\-]{20,})"',
        r'"token"\s*:\s*"(\$[a-zA-Z0-9_/+=\-]{20,})"',
        r'"(\$[a-zA-Z0-9_/+=\-]{30,})"',
    ]
    for pat in patterns:
        m = re.search(pat, html)
        if m:
            return m.group(1)
    return None


def token_from_frames(page):
    """Попробовать window.config.auth_token в каждом фрейме."""
    for frame in page.frames:
        for expr in [
            "typeof window.config !== 'undefined' && window.config.auth_token",
            "typeof window.__INIT_STATE__ !== 'undefined' "
            "&& JSON.stringify(window.__INIT_STATE__)",
        ]:
            try:
                val = frame.evaluate(expr)
                if isinstance(val, str) and val.startswith("$") and len(val) > 20:
                    return val
                # __INIT_STATE__ может содержать вложенный auth_token
                if isinstance(val, str) and "auth_token" in val:
                    tok = token_from_html(val)
                    if tok:
                        return tok
            except Exception:
                continue
    return None


def is_login_page(url):
    return any(x in url for x in ["/login", "/authorize", "act=login", "oauth.vk.com"])


def get_token(url, headless=True, timeout_ms=30000):
    """Главная функция: открыть страницу, найти токен."""
    BROWSER_DIR.mkdir(parents=True, exist_ok=True)

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            str(BROWSER_DIR),
            headless=headless,
            locale="ru-RU",
            viewport={"width": 1280, "height": 720},
            args=["--disable-blink-features=AutomationControlled"],
        )

        page = context.pages[0] if context.pages else context.new_page()
        found = None

        def on_request(req):
            nonlocal found
            if found:
                return
            if "fb.do" in req.url and req.method == "POST":
                tok = token_from_post(req)
                if tok:
                    log(f"intercepted from fb.do request")
                    found = tok

        page.on("request", on_request)

        # ── Открываем страницу ────────────────────────────────
        log(f"opening {url}")
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        except PwTimeout:
            log("page load timed out (continuing anyway)")
        except Exception as e:
            log(f"goto error: {e}")

        # Ждём JS и сетевые запросы
        try:
            page.wait_for_timeout(5000)
        except Exception:
            pass

        if found:
            context.close()
            return found

        # ── Поиск в HTML ──────────────────────────────────────
        try:
            html = page.content()
            found = token_from_html(html)
            if found:
                log("found in page HTML")
        except Exception:
            pass

        if found:
            context.close()
            return found

        # ── Поиск через JS evaluation ────────────────────────
        found = token_from_frames(page)
        if found:
            log("found via JS evaluation")
            context.close()
            return found

        # ── Если страница логина ──────────────────────────────
        current = page.url
        if is_login_page(current):
            if headless:
                log("VK redirected to login page")
                log("run with --login flag first to authenticate")
                context.close()
                return None

            # Видимый режим — ждём пока пользователь залогинится
            log("VK login required — please log in in the browser window")
            log("waiting up to 2 minutes...")

            try:
                page.wait_for_url(
                    lambda u: "call" in u or "im" in u,
                    timeout=120000,
                )
            except PwTimeout:
                log("login timeout (2 min)")
                context.close()
                return None

            log("login detected, reloading call page...")
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            except Exception:
                pass

            try:
                page.wait_for_timeout(5000)
            except Exception:
                pass

            # Повторный поиск
            if not found:
                try:
                    html = page.content()
                    found = token_from_html(html)
                except Exception:
                    pass
            if not found:
                found = token_from_frames(page)

        context.close()
        return found


def main():
    parser = argparse.ArgumentParser(
        description="Extract OK auth_token from a VK call page"
    )
    parser.add_argument("url", help="VK call/join URL")
    parser.add_argument(
        "--login",
        action="store_true",
        help="Open visible browser for VK login (run once)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Page load timeout in seconds (default: 30)",
    )
    args = parser.parse_args()

    headless = not args.login
    token = get_token(args.url, headless=headless, timeout_ms=args.timeout * 1000)

    if token:
        # Печатаем ТОЛЬКО токен на stdout (stderr — для логов)
        print(token)
        sys.exit(0)
    else:
        log("could not extract auth_token")
        sys.exit(1)


if __name__ == "__main__":
    main()