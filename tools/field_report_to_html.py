#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Convert the markdown produced by the device-side pmon_field_report.py into HTML (reusing the
buildimage FAULT_INJECTION_REPORT.html layout: gray background with white sheet, terminal-colored code blocks, red/green verdict tags).

Usage:
    python3 tools/field_report_to_html.py <in.md> [out.html]
"""
import html
import re
import sys

CSS = """
:root{--page:#e9ebee;--sheet:#fff;--ink:#22272e;--muted:#5b6470;--line:#d7dce2;
--line-soft:#e7eaee;--accent:#2f5d8f;--red:#b13a30;--green:#2f7d4a;
--term-bg:#16191e;--term-ink:#cfd7e0;--term-cmd:#8fbbe8;}
@media (prefers-color-scheme:dark){:root{--page:#101216;--sheet:#191d23;
--ink:#d5dae1;--muted:#8b94a0;--line:#333a43;--line-soft:#272d35;--accent:#7aaad8;
--red:#e0705f;--green:#67b083;--term-bg:#0d0f12;--term-ink:#c4ccd6;--term-cmd:#82b3e6;}}
*{box-sizing:border-box}
body{margin:0;background:var(--page);color:var(--ink);
font:15px/1.75 -apple-system,"Segoe UI","PingFang SC","Microsoft YaHei","Noto Sans CJK SC",sans-serif;}
.sheet{max-width:960px;margin:24px auto 64px;background:var(--sheet);
border:1px solid var(--line);padding:48px 56px 64px;}
@media (max-width:720px){.sheet{margin:0;padding:24px 16px}}
h1{font-size:25px;line-height:1.4;margin:0 0 4px;text-wrap:balance}
.subtitle{color:var(--muted);margin:0 0 24px}
h2{font-size:19px;margin:52px 0 12px;padding-bottom:8px;border-bottom:2px solid var(--ink)}
h3{font-size:15px;margin:26px 0 8px;color:var(--accent);
font-family:ui-monospace,Consolas,monospace}
p,li{margin:8px 0;max-width:52em}
ul{margin:8px 0}
b.bad{color:var(--red)}b.ok{color:var(--green)}
.tag{display:inline-block;font-size:12px;font-weight:600;padding:1px 8px;
margin-left:6px;border-radius:2px;letter-spacing:.03em}
.tag.red{color:var(--red);border:1px solid var(--red)}
.tag.green{color:var(--green);border:1px solid var(--green)}
.tag.gray{color:var(--muted);border:1px solid var(--muted)}
.status{font-size:13px;color:var(--muted);margin:4px 0 8px}
.mono,code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
pre.term{background:var(--term-bg);color:var(--term-ink);font-size:12.5px;
line-height:1.55;padding:14px 16px;margin:0 0 18px;overflow-x:auto;border:1px solid var(--line)}
pre.term .cmd{color:var(--term-cmd);font-weight:600}
.toc{border:1px solid var(--line);padding:14px 18px;margin:22px 0;font-size:14px}
.toc a{color:var(--accent);text-decoration:none}.toc a:hover{text-decoration:underline}
.note{border-left:3px solid var(--accent);background:var(--line-soft);
padding:10px 14px;margin:14px 0;font-size:14px;max-width:none}
.footer{margin-top:48px;padding-top:12px;border-top:1px solid var(--line);
color:var(--muted);font-size:13px}
"""


def esc(s):
    return html.escape(s, quote=False)


def term(lines):
    out = []
    for ln in lines:
        e = esc(ln)
        out.append('<span class="cmd">%s</span>' % e if ln.startswith("$ ") else e)
    return '<pre class="term">%s</pre>' % "\n".join(out)


def verdict_tag(text):
    if "✅" in text or "Auto-recover" in text and "🔴" not in text:
        return '<span class="tag green">Auto-recoverable</span>'
    if "🔴" in text:
        return '<span class="tag red">Not auto-recoverable</span>'
    if "skipped" in text:
        return '<span class="tag gray">Skipped</span>'
    return ""


def convert(md):
    lines = md.splitlines()
    body, toc, i = [], [], 0
    sec_n = 0
    in_code, code = False, []
    while i < len(lines):
        ln = lines[i]
        if ln.strip().startswith("```"):
            if in_code:
                body.append(term(code))
                code, in_code = [], False
            else:
                in_code = True
            i += 1
            continue
        if in_code:
            code.append(ln)
            i += 1
            continue
        if ln.startswith("# "):
            body.append("<h1>%s</h1>" % esc(ln[2:]))
        elif ln.startswith("> "):
            # collapse consecutive blockquotes into a subtitle/description
            quote = [ln[2:]]
            while i + 1 < len(lines) and lines[i + 1].startswith("> "):
                i += 1
                quote.append(lines[i][2:])
            body.append('<p class="subtitle">%s</p>' % esc(" ".join(quote)))
        elif ln.startswith("## "):
            sec_n += 1
            title = ln[3:]
            anchor = "s%d" % sec_n
            toc.append('<li><a href="#%s">%s</a></li>' % (anchor, esc(title)))
            body.append('<h2 id="%s">%s</h2>' % (anchor, esc(title)))
        elif ln.startswith("### "):
            body.append("<h3>%s</h3>" % esc(ln[4:]))
        elif ln.startswith("- "):
            item = ln[2:]
            tag = ""
            if "Auto-recover" in item or "Result" in item:
                tag = verdict_tag(item)
            item = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", item)
            cls = ' class="status"' if item.startswith("daemons") else ""
            body.append("<p%s>%s %s</p>" % (cls, esc_inline(item), tag))
        elif ln.strip():
            body.append("<p>%s</p>" % esc_inline(ln))
        i += 1
    toc_html = '<div class="toc"><b>Contents</b><ul>%s</ul></div>' % "".join(toc)
    # insert the toc right after the first h1
    for k, seg in enumerate(body):
        if seg.startswith("<h1"):
            body.insert(k + 1, toc_html)
            break
    return ("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>pmon Faulty-Device Field Test Report</title><style>%s</style></head><body>"
            "<div class=\"sheet\">%s<div class=\"footer\">This report was generated by "
            "tools/pmon_field_report.py from a live on-device test run, and "
            "converted into this page by tools/field_report_to_html.py.</div></div></body></html>"
            % (CSS, "\n".join(body)))


def esc_inline(s):
    s = re.sub(r"\*\*(.+?)\*\*", lambda m: "\x00%s\x01" % m.group(1), s)
    s = re.sub(r"`(.+?)`", lambda m: "\x02%s\x03" % m.group(1), s)
    s = html.escape(s, quote=False)
    s = s.replace("\x00", "<b>").replace("\x01", "</b>")
    s = s.replace("\x02", "<code>").replace("\x03", "</code>")
    return s


def main():
    if len(sys.argv) < 2:
        print("usage: field_report_to_html.py <in.md> [out.html]", file=sys.stderr)
        return 1
    inp = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else inp.rsplit(".", 1)[0] + ".html"
    with open(inp) as f:
        md = f.read()
    with open(out, "w") as f:
        f.write(convert(md))
    print("written: %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
