#!/usr/bin/env python3
"""Render web/og.html to web/assets/og.png at 1200x630.

Run this after changing og.html, then rebuild and commit the PNG. It is kept
out of the normal build because it is the one step that needs a browser, and
the site must stay buildable with nothing but the standard library.

    pip install playwright && playwright install chromium
    python3 web/scripts/make_og.py
"""

import pathlib
import sys

WEB = pathlib.Path(__file__).resolve().parent.parent
SOURCE = WEB / "og.html"
TARGET = WEB / "assets" / "og.png"


def main():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("needs playwright: pip install playwright && playwright install chromium")
        return 1

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1200, "height": 630})
        page.goto(SOURCE.as_uri())
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(500)
        page.screenshot(path=str(TARGET))
        browser.close()

    print(f"wrote {TARGET} ({TARGET.stat().st_size / 1024:.0f} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
