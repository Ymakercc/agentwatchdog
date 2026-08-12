#!/usr/bin/env python3
"""Render the site from one template and one content file per language.

Why this exists: the site is bilingual, and two hand-maintained HTML files
drift. The Chinese page silently falls a release behind the English one and
nobody notices until someone reads it. Keeping structure in one place makes
that impossible rather than merely discouraged.

Why it is not a framework: the page has two pieces of behaviour and no state.
A build step that emits static HTML costs nothing at runtime, needs no
node_modules, and cannot break a deploy. The output is committed, so
Cloudflare Pages serves `site/` with no build command at all; CI checks the
committed output still matches a fresh build.

    python3 web/build.py           # write site/
    python3 web/build.py --check   # fail if site/ is stale (CI)

Standard library only, like everything else here.
"""

import html
import json
import pathlib
import re
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parent
OUT = ROOT.parent / "site"

LANGS = [
    {"code": "en", "content": "content.en.json", "path": ""},
    {"code": "zh", "content": "content.zh.json", "path": "zh/"},
]


# ---------------------------------------------------------------------------
# Inline markup
#
# Content files hold text, not HTML, so a copy edit cannot break the page or
# inject markup. Everything is escaped first; only these four marks survive.
# ---------------------------------------------------------------------------
def inline(text):
    """Escape text, then expand the four inline marks used in content files.

    ``[[x]]``  a span the redaction bar covers   ``→`` <span class="rd">
    ``` `x` ```  literal / identifier            ``→`` <code>
    ``**x**``  emphasis that carries the verdict  ``→`` <strong>
    ``{label|href}``  link                        ``→`` <a>
    """
    out = html.escape(str(text), quote=False)
    out = re.sub(r"\[\[(.+?)\]\]", r'<span class="rd">\1</span>', out)
    out = re.sub(r"`(.+?)`", r"<code>\1</code>", out)
    out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"\{([^}|]+)\|([^}]+)\}", r'<a href="\2">\1</a>', out)
    return out


def attr(text):
    """Escape for an attribute value."""
    return html.escape(str(text), quote=True)


def tag(text, classes=""):
    """Render a margin label.

    ``code`` labels are real identifiers from the source tree, so they keep
    their own casing — upper-casing `test_environ_is_never_opened` would print
    something that does not exist. They are long, so break opportunities go in
    at the underscores, which is where a reader would break them anyway.
    """
    names = classes.split() if classes else []
    suffix = "".join(" tag--" + name for name in names)
    body = inline(text)
    if "code" in names:
        body = body.replace("_", "_<wbr>")
    return f'<p class="tag{suffix}">{body}</p>'


def paragraphs(value, cls=""):
    """Render a string or list of strings as <p> elements."""
    items = value if isinstance(value, list) else [value]
    klass = f' class="{cls}"' if cls else ""
    return "\n".join(f"<p{klass}>{inline(p)}</p>" for p in items)


# ---------------------------------------------------------------------------
# Blocks
# ---------------------------------------------------------------------------
def render_head(content, lang):
    meta = content["meta"]
    other = "zh" if lang["code"] == "en" else "en"
    return f"""<title>{inline(meta["title"])}</title>
<meta name="description" content="{attr(meta["description"])}">
<link rel="canonical" href="{attr(meta["canonical"])}">
<link rel="alternate" hreflang="en" href="https://31582749.xyz/">
<link rel="alternate" hreflang="zh-Hans" href="https://31582749.xyz/zh/">
<link rel="alternate" hreflang="x-default" href="https://31582749.xyz/">
<meta property="og:type" content="website">
<meta property="og:locale" content="{"en_US" if lang["code"] == "en" else "zh_CN"}">
<meta property="og:url" content="{attr(meta["canonical"])}">
<meta property="og:title" content="{attr(meta["og_title"])}">
<meta property="og:description" content="{attr(meta["og_description"])}">
<meta property="og:image" content="https://31582749.xyz/assets/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<!-- other language: {other} -->"""


def render_nav(content, lang):
    nav = content["nav"]
    links = "\n      ".join(
        f'<a class="navlink" href="{attr(item["href"])}">{inline(item["label"])}</a>'
        for item in nav["sections"]
    )
    en_current = ' aria-current="true"' if lang["code"] == "en" else ""
    zh_current = ' aria-current="true"' if lang["code"] == "zh" else ""
    return f"""{links}
      <a class="masthead__gh" href="https://github.com/Ymakercc/agentwatchdog">{inline(nav["github"])}&#8239;↗</a>
      <span class="lang">
        <a href="/"{en_current} lang="en">EN</a>
        <a href="/zh/"{zh_current} lang="zh-Hans">中文</a>
      </span>"""


def render_scan(scan):
    lines = []
    for line in scan["lines"]:
        note = f"<b>{inline(line['note'])}</b>" if line.get("note") else ""
        lines.append(
            f"""        <div class="line">
          <span class="line__src">{inline(line["src"])}</span>
          <code class="line__cmd">{inline(line["cmd"])}</code>
          <span class="line__rule">{inline(line["rule"])}{note}</span>
        </div>"""
        )
    return f"""    <div class="scan" data-scan>
      <div class="scan__bar">
        <span class="scan__pulse" aria-hidden="true"></span>
        <span>{inline(scan["title"])}</span>
        <button type="button" class="scan__replay" data-replay>{inline(scan["replay"])}</button>
      </div>

      <div class="scan__body">
{chr(10).join(lines)}
      </div>

      <p class="scan__caption">{inline(scan["caption"])}</p>
    </div>"""


def render_hero(content):
    hero = content["hero"]
    cta = hero["cta"]
    copy_attrs = f'data-copy="{attr(cta["command"])}" data-copied-label="{attr(cta["copied"])}"'
    return f"""  <section class="hero wrap">
    <p class="tag hero__eyebrow">{inline(hero["eyebrow"])}</p>

    <h1>{inline(hero["h1"])}</h1>

    <p class="lead hero__lead">{inline(hero["lead"])}</p>

{render_scan(hero["scan"])}

    <div class="hero__cta">
      <button type="button" class="copy" {copy_attrs}>
        <span>{inline(cta["command"])}</span>
        <span class="copy__label">{inline(cta["copy"])}</span>
      </button>
      <p class="hero__note">{inline(cta["note"])}</p>
    </div>
  </section>"""


def render_section_head(section):
    intro = paragraphs(section["intro"]) if section.get("intro") else ""
    return f"""    <div class="section__head">
      <p class="tag">{inline(section["tag"])}</p>
      <div>
        <h2>{inline(section["h2"])}</h2>
        {intro}
      </div>
    </div>"""


def render_ledger(section):
    head = section["head"]
    rows = []
    for row in section["rows"]:
        us = inline(row["us"])
        rows.append(
            f"""      <div class="ledger__row">
        <dt>{inline(row["label"])}</dt>
        <dd class="ledger__them" data-label="{attr(head["them"])}">{inline(row["them"])}</dd>
        <dd class="ledger__us" data-label="{attr(head["us"])}">{us}</dd>
      </div>"""
        )
    return f"""    <dl class="ledger">
      <div class="ledger__head" aria-hidden="true">
        <dt>&nbsp;</dt>
        <dd class="ledger__them tag">{inline(head["them"])}</dd>
        <dd class="ledger__us tag tag--signal">{inline(head["us"])}</dd>
      </div>

{chr(10).join(rows)}
    </dl>"""


def render_rows(section):
    items = []
    for row in section["rows"]:
        refs = [tag(row["tag"], row.get("tag_class", ""))]
        if row.get("severity"):
            refs.append(tag(row["severity"], "critical" if row.get("severity_critical") else ""))
        heading = f"<h3>{inline(row['h3'])}</h3>" if row.get("h3") else ""
        items.append(
            f"""      <article class="row">
        <div class="row__ref">
          {chr(10).join("          " + r for r in refs).strip()}
        </div>
        <div class="row__body">
          {heading}
          {paragraphs(row["body"])}
        </div>
      </article>"""
        )
    return f'    <div class="rows">\n{chr(10).join(items)}\n    </div>'


def render_table(section):
    heads = "".join(f'<th scope="col">{inline(c)}</th>' for c in section["columns"])
    body = []
    for row in section["rows"]:
        confidence = "verified" if row["verified"] else "best-effort"
        cells = [
            f"<td>{inline(row['agent'])}</td>",
            f'<td class="{confidence}">{inline(row["flags"])}</td>',
            f'<td class="dim">{inline(row["prompt"])}</td>',
        ]
        body.append(f"        <tr>{''.join(cells)}</tr>")
    return f"""    <table class="agents">
      <thead>
        <tr>{heads}</tr>
      </thead>
      <tbody>
{chr(10).join(body)}
      </tbody>
    </table>"""


def render_steps(section):
    items = []
    for step in section["steps"]:
        lines = []
        for line in step["lines"]:
            if line.startswith("#"):
                lines.append(f'<span class="c">{html.escape(line)}</span>')
            else:
                lines.append(f'<span class="p">$ </span>{html.escape(line)}')
        note = f'<p class="install__note">{inline(step["note"])}</p>' if step.get("note") else ""
        items.append(
            f"""      <article class="row">
        <div class="row__ref"><p class="tag">{inline(step["tag"])}</p></div>
        <div class="row__body">
<pre><code>{chr(10).join(lines)}</code></pre>
          {note}
        </div>
      </article>"""
        )
    return f'    <div class="rows">\n{chr(10).join(items)}\n    </div>'


BODIES = {
    "ledger": render_ledger,
    "rows": render_rows,
    "table": render_table,
    "steps": render_steps,
}


def render_sections(content):
    out = []
    for section in content["sections"]:
        note = (
            f'\n    <p class="install__note">{inline(section["note"])}</p>'
            if section.get("note")
            else ""
        )
        out.append(
            f"""  <section class="section wrap" id="{attr(section["id"])}">
{render_section_head(section)}

{BODIES[section["type"]](section)}{note}
  </section>"""
        )
    return "\n\n".join(out)


def render_closing(content):
    closing = content["closing"]
    links = "\n      ".join(
        f'<a href="{attr(link["href"])}">{inline(link["label"])}&#8239;↗</a>'
        for link in closing["links"]
    )
    return f"""  <section class="closing wrap">
    <h2>{inline(closing["h2"])}</h2>
    <div class="closing__actions">
      {links}
    </div>
  </section>"""


def render_footer(content, lang):
    footer = content["footer"]
    other = '<a href="/zh/">中文</a>' if lang["code"] == "en" else '<a href="/">English</a>'
    return f"""  <div class="wrap footer__grid">
    <p class="tag">{inline(footer["tag"])}</p>
    <div>
      {paragraphs(footer["notes"])}
      <p><a href="https://github.com/Ymakercc/agentwatchdog">GitHub</a> &middot; {other}</p>
    </div>
  </div>"""


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------
def render_page(template, content, lang):
    return (
        template.replace("{{LANG}}", "en" if lang["code"] == "en" else "zh-Hans")
        .replace("{{HEAD}}", render_head(content, lang))
        .replace("{{SKIP}}", inline(content["nav"]["skip"]))
        .replace("{{NAV}}", render_nav(content, lang))
        .replace("{{HERO}}", render_hero(content))
        .replace("{{SECTIONS}}", render_sections(content))
        .replace("{{CLOSING}}", render_closing(content))
        .replace("{{FOOTER}}", render_footer(content, lang))
    )


def build():
    """Return {relative path: file bytes} for the whole site."""
    template = (ROOT / "template.html").read_text(encoding="utf-8")
    files = {}

    for lang in LANGS:
        content = json.loads((ROOT / lang["content"]).read_text(encoding="utf-8"))
        page = render_page(template, content, lang)
        files[lang["path"] + "index.html"] = page.encode("utf-8")

    for path in sorted((ROOT / "assets").rglob("*")):
        if path.is_file():
            files["assets/" + str(path.relative_to(ROOT / "assets"))] = path.read_bytes()

    for name in ("_headers", "robots.txt", "sitemap.xml", "404.html"):
        source = ROOT / name
        if source.exists():
            files[name] = source.read_bytes()

    return files


def main(argv):
    files = build()

    if "--check" in argv:
        stale = []
        for name, data in files.items():
            target = OUT / name
            if not target.exists() or target.read_bytes() != data:
                stale.append(name)
        extra = [
            str(p.relative_to(OUT))
            for p in OUT.rglob("*")
            if p.is_file() and str(p.relative_to(OUT)) not in files
        ]
        if stale or extra:
            print("site/ is out of date; run: python3 web/build.py")
            for name in stale:
                print(f"  changed  {name}")
            for name in extra:
                print(f"  orphan   {name}")
            return 1
        print(f"site/ is up to date ({len(files)} files)")
        return 0

    if OUT.exists():
        shutil.rmtree(OUT)
    for name, data in files.items():
        target = OUT / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    total = sum(len(d) for d in files.values())
    print(f"built {len(files)} files into {OUT} ({total / 1024:.0f} KB)")
    for name in sorted(files):
        if name.endswith((".html", ".css", ".js")):
            print(f"  {len(files[name]) / 1024:6.1f} KB  {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
