#!/usr/bin/env python3
"""
Build script for SCEF Browser Viewer.
Inlines all JS, CSS, and vendor libs into a single dist/index.html.

Usage: python build.py
"""

import os
import re

BROWSER_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(BROWSER_DIR, 'dist')
INDEX_PATH = os.path.join(BROWSER_DIR, 'index.html')


def read_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()


def inline_css(html):
    """Replace <link rel="stylesheet" href="..."> with inline <style>."""
    def replacer(match):
        href = match.group(1)
        css_path = os.path.join(BROWSER_DIR, href)
        css = read_file(css_path)
        return '<style>\n' + css + '\n</style>'

    return re.sub(
        r'<link\s+rel="stylesheet"\s+href="([^"]+)"\s*/?>',
        replacer,
        html
    )


def inline_scripts(html):
    """Replace <script src="..."></script> with inline <script>."""
    def replacer(match):
        src = match.group(1)
        js_path = os.path.join(BROWSER_DIR, src)
        js = read_file(js_path)
        return '<script>\n' + js + '\n</script>'

    return re.sub(
        r'<script\s+src="([^"]+)"\s*>\s*</script>',
        replacer,
        html
    )


def remove_dev_comments(html):
    """Remove development-only HTML comments."""
    return re.sub(r'\s*<!--.*?-->\s*', '\n', html)


def build():
    os.makedirs(DIST_DIR, exist_ok=True)

    html = read_file(INDEX_PATH)
    html = inline_css(html)
    html = inline_scripts(html)
    html = remove_dev_comments(html)

    out_path = os.path.join(DIST_DIR, 'index.html')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(html)

    size_kb = os.path.getsize(out_path) / 1024
    print(f'Built: {out_path}')
    print(f'Size: {size_kb:.1f} KiB')


if __name__ == '__main__':
    build()
