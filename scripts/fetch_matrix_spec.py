#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Downloads all Matrix v1.18 spec pages and converts them to Markdown.
# Output: docs/matrix-v1.18-spec/

import urllib.request
import re
import os
import sys
from html.parser import HTMLParser


class MatrixSpecConverter(HTMLParser):
    """SAX-style HTML-to-Markdown converter tuned for the Matrix spec site.

    Skip logic
    ----------
    A naive counter (_skip += 1 per start-tag, -= 1 per end-tag) breaks
    because HTML5 void elements (<meta>, <link>, <br>, etc.) never fire an
    end-tag event.  Inside a skipped subtree those void elements would
    inflate the counter permanently and suppress all subsequent output.

    Fix: use a boolean flag (_in_skip) plus a separate depth counter
    (_skip_depth) that only tracks *non-void* child tags.  Void elements
    are never counted so they cannot leave the counter unbalanced.
    """

    SKIP = {
        "script", "style", "noscript", "svg", "path", "defs", "symbol",
        "use", "mask", "g", "circle", "rect", "line", "polyline", "polygon",
        "header", "footer", "nav", "aside", "button", "input", "form",
        "select", "option", "label", "meta", "link", "base", "head",
        "figure",
    }
    VOID = {
        "br", "hr", "img", "input", "meta", "link", "base", "area", "col",
        "embed", "param", "source", "track", "wbr",
    }

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._out = []
        self._in_skip = False   # inside a skipped subtree?
        self._skip_depth = 0    # non-void child tag depth inside the subtree
        self._tags = []
        self._list = []
        self._li_idx = []
        self._in_pre = False
        self._in_code = False
        self._in_th = False
        self._in_td = False
        self._in_a = False
        self._a_href = ""
        self._a_text = []
        self._pending_nl = 0
        self._cell_buf = []
        self._row = []
        self._rows = []
        self._is_header_row = False
        self._pre_buf = []
        self._pre_lang = ""

    # ------------------------------------------------------------------ output

    def _emit(self, s):
        if not s:
            return
        if self._in_pre:
            self._pre_buf.append(s)
            return
        if self._in_th or self._in_td:
            self._cell_buf.append(s)
            return
        if self._pending_nl:
            if s.strip():
                self._out.append("\n" * self._pending_nl)
                self._pending_nl = 0
            else:
                return
        self._out.append(s)

    def _nl(self, n=1):
        self._pending_nl = max(self._pending_nl, n)

    def _flush_pre(self):
        content = "".join(self._pre_buf).rstrip("\n")
        lang = self._pre_lang or ""
        self._out.append(f"\n\n```{lang}\n{content}\n```\n\n")
        self._pre_buf = []
        self._pre_lang = ""

    # ------------------------------------------------------------------ parser

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        ad = dict(attrs)

        # --- skip logic --------------------------------------------------
        if self._in_skip:
            # Only non-void children change the depth (void never close).
            if tag not in self.VOID:
                self._skip_depth += 1
            return
        if tag in self.SKIP:
            self._in_skip = True
            self._skip_depth = 0
            return

        # --- void elements (no end-tag) ----------------------------------
        if tag in self.VOID:
            if tag == "br":
                self._emit("\n")
            elif tag == "hr":
                self._nl(2)
                self._emit("---")
                self._nl(2)
            return

        # --- block / inline elements -------------------------------------
        self._tags.append(tag)

        if tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._nl(2)
            self._emit("#" * int(tag[1]) + " ")
        elif tag == "p":
            self._nl(2)
        elif tag == "pre":
            self._in_pre = True
            cls = ad.get("class", "")
            for part in cls.split():
                if part.startswith("language-"):
                    self._pre_lang = part[9:]
                    break
        elif tag == "code" and not self._in_pre:
            self._in_code = True
            self._emit("`")
        elif tag in ("ul", "ol"):
            self._list.append(tag)
            self._li_idx.append(0)
            self._nl(1)
        elif tag == "li":
            depth = len(self._list) - 1
            indent = "  " * depth
            if self._list and self._list[-1] == "ol":
                self._li_idx[-1] += 1
                self._emit(f"\n{indent}{self._li_idx[-1]}. ")
            else:
                self._emit(f"\n{indent}- ")
        elif tag == "a":
            self._in_a = True
            self._a_href = ad.get("href", "")
            self._a_text = []
        elif tag in ("strong", "b"):
            self._emit("**")
        elif tag in ("em", "i"):
            self._emit("*")
        elif tag == "blockquote":
            self._nl(2)
        elif tag == "table":
            self._rows = []
        elif tag == "thead":
            self._is_header_row = True
        elif tag == "tbody":
            self._is_header_row = False
        elif tag == "tr":
            self._row = []
        elif tag in ("th", "td"):
            self._in_th = tag == "th"
            self._in_td = tag == "td"
            self._cell_buf = []

    def handle_endtag(self, tag):
        tag = tag.lower()

        # --- skip logic --------------------------------------------------
        if self._in_skip:
            if self._skip_depth > 0:
                self._skip_depth -= 1
            else:
                self._in_skip = False
            return

        if tag in self.VOID:
            return

        if self._tags and self._tags[-1] == tag:
            self._tags.pop()

        if tag in ("h1", "h2", "h3", "h4", "h5", "h6"):
            self._nl(2)
        elif tag == "p":
            self._nl(2)
        elif tag == "pre":
            self._in_pre = False
            self._flush_pre()
        elif tag == "code" and self._in_code:
            self._in_code = False
            self._emit("`")
        elif tag in ("ul", "ol"):
            if self._list:
                self._list.pop()
                self._li_idx.pop()
            self._nl(2)
        elif tag == "a":
            self._in_a = False
            text = "".join(self._a_text).strip()
            href = self._a_href
            if text and href and not href.startswith("javascript"):
                if href.startswith("#"):
                    self._emit(text)
                else:
                    self._emit(f"[{text}]({href})")
            elif text:
                self._emit(text)
            self._a_text = []
        elif tag in ("strong", "b"):
            self._emit("**")
        elif tag in ("em", "i"):
            self._emit("*")
        elif tag in ("th", "td"):
            cell = re.sub(r"\s+", " ", "".join(self._cell_buf)).strip()
            self._row.append(cell)
            self._cell_buf = []
            self._in_th = False
            self._in_td = False
        elif tag == "tr":
            self._rows.append((self._is_header_row, self._row[:]))
            self._row = []
        elif tag == "table":
            self._emit_table()
        elif tag == "blockquote":
            self._nl(2)
        elif tag in ("div", "section", "article", "main"):
            self._nl(1)

    def _emit_table(self):
        if not self._rows:
            return
        self._nl(2)
        max_cols = max((len(r[1]) for r in self._rows), default=0)
        if max_cols == 0:
            return
        header_emitted = False
        first = True
        for is_hdr, cells in self._rows:
            cells = cells + [""] * (max_cols - len(cells))
            row_str = (
                "| "
                + " | ".join(
                    c.replace("|", "\\|").replace("\n", " ") for c in cells
                )
                + " |"
            )
            self._out.append(row_str + "\n")
            if (is_hdr or first) and not header_emitted:
                sep = "|" + "|".join(" --- " for _ in cells) + "|"
                self._out.append(sep + "\n")
                header_emitted = True
            first = False
        self._nl(2)

    def handle_data(self, data):
        if self._in_skip:
            return
        if self._in_pre:
            self._pre_buf.append(data)
            return
        if self._in_a:
            self._a_text.append(data)
        if self._in_th or self._in_td:
            self._cell_buf.append(data)
            return
        if not self._in_code:
            data = re.sub(r"[ \t]+", " ", data)
            if data == " " and (not self._out or self._out[-1].endswith("\n")):
                return
        self._emit(data)

    def result(self):
        text = "".join(self._out)
        text = re.sub(r"\n{4,}", "\n\n\n", text)
        return text.strip() + "\n"


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read().decode("utf-8", errors="replace")


def html_to_md(html):
    p = MatrixSpecConverter()
    p.feed(html)
    return p.result()


def save(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)


BASE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "docs", "matrix-v1.18-spec",
)

PAGES = [
    ("https://spec.matrix.org/v1.18/",                         "index.md"),
    ("https://spec.matrix.org/v1.18/client-server-api/",       "client-server-api.md"),
    ("https://spec.matrix.org/v1.18/server-server-api/",       "server-server-api.md"),
    ("https://spec.matrix.org/v1.18/application-service-api/", "application-service-api.md"),
    ("https://spec.matrix.org/v1.18/identity-service-api/",    "identity-service-api.md"),
    ("https://spec.matrix.org/v1.18/push-gateway-api/",        "push-gateway-api.md"),
    ("https://spec.matrix.org/v1.18/rooms/",                   "rooms/index.md"),
    ("https://spec.matrix.org/v1.18/rooms/v1/",                "rooms/v1.md"),
    ("https://spec.matrix.org/v1.18/rooms/v2/",                "rooms/v2.md"),
    ("https://spec.matrix.org/v1.18/rooms/v3/",                "rooms/v3.md"),
    ("https://spec.matrix.org/v1.18/rooms/v4/",                "rooms/v4.md"),
    ("https://spec.matrix.org/v1.18/rooms/v5/",                "rooms/v5.md"),
    ("https://spec.matrix.org/v1.18/rooms/v6/",                "rooms/v6.md"),
    ("https://spec.matrix.org/v1.18/rooms/v7/",                "rooms/v7.md"),
    ("https://spec.matrix.org/v1.18/rooms/v8/",                "rooms/v8.md"),
    ("https://spec.matrix.org/v1.18/rooms/v9/",                "rooms/v9.md"),
    ("https://spec.matrix.org/v1.18/rooms/v10/",               "rooms/v10.md"),
    ("https://spec.matrix.org/v1.18/rooms/v11/",               "rooms/v11.md"),
    ("https://spec.matrix.org/v1.18/rooms/v12/",               "rooms/v12.md"),
    ("https://spec.matrix.org/v1.18/appendices/",              "appendices.md"),
]

errors = []
for url, rel in PAGES:
    path = os.path.join(BASE, rel)
    try:
        print(f"  fetching {url} ...", end=" ", flush=True)
        html = fetch(url)
        md = html_to_md(html)
        save(path, md)
        kb = len(md) // 1024
        print(f"ok  {kb:>4}KB  ->  {rel}")
    except Exception as exc:
        msg = f"FAILED {url}: {exc}"
        errors.append(msg)
        print(f"\n  ERROR: {exc}", file=sys.stderr)

print()
if errors:
    print(f"{len(errors)} page(s) failed:")
    for e in errors:
        print(f"  {e}")
    sys.exit(1)
else:
    print(f"All {len(PAGES)} pages saved to docs/matrix-v1.18-spec/")
