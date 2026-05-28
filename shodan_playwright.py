"""
Shodan query via authenticated Playwright browser session.
Uses fetch() from within a logged-in Shodan page via page.evaluate().
Falls back gracefully if browser is not available or session is not authenticated.
"""

import json
import os
from typing import Optional

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    _PW_AVAILABLE = True
except ImportError:
    _PW_AVAILABLE = False


def _make_fetch_js(url: str) -> str:
    """JS snippet that calls the Shodan API from within the authenticated browser session."""
    return f"""
    async () => {{
        try {{
            const r = await fetch({json.dumps(url)}, {{
                credentials: 'include',
                headers: {{'Accept': 'application/json'}}
            }});
            const text = await r.text();
            return {{status: r.status, body: text}};
        }} catch(e) {{
            return {{status: 0, body: e.toString()}};
        }}
    }}
    """


def shodan_count(dork: str) -> Optional[int]:
    """Return count of Shodan results for dork. None on failure."""
    if not _PW_AVAILABLE:
        return None

    import urllib.parse
    encoded = urllib.parse.quote(dork)
    api_url = f"https://api.shodan.io/shodan/host/count?query={encoded}"

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context()
            page = ctx.new_page()

            # Navigate to Shodan so session cookies apply
            page.goto("https://www.shodan.io/", timeout=15000, wait_until="domcontentloaded")

            result = page.evaluate(_make_fetch_js(api_url))
            browser.close()

            if result.get("status") != 200:
                return None
            data = json.loads(result["body"])
            return data.get("total")
    except Exception:
        return None


def shodan_search(dork: str, limit: int = 20) -> list[dict]:
    """Return list of host records from Shodan search. Empty on failure."""
    if not _PW_AVAILABLE:
        return []

    import urllib.parse
    encoded = urllib.parse.quote(dork)
    api_url = (
        f"https://api.shodan.io/shodan/host/search"
        f"?query={encoded}&fields=ip_str,port,org,hostnames,product&page=1"
    )

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx = browser.new_context()
            page = ctx.new_page()

            page.goto("https://www.shodan.io/", timeout=15000, wait_until="domcontentloaded")

            result = page.evaluate(_make_fetch_js(api_url))
            browser.close()

            if result.get("status") != 200:
                return []
            data = json.loads(result["body"])
            return data.get("matches", [])[:limit]
    except Exception:
        return []


def shodan_count_via_mcp_js(dork: str, api_key: str) -> Optional[int]:
    """
    Shodan count using direct API key (when valid key is available).
    Kept as reference; use shodan_count() for session-based approach.
    """
    import urllib.parse
    import urllib.request
    encoded = urllib.parse.quote(dork)
    url = f"https://api.shodan.io/shodan/host/count?key={api_key}&query={encoded}"
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            return json.loads(r.read()).get("total")
    except Exception:
        return None
