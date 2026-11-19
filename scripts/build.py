#!/usr/bin/env python3
# =============================================================================
#  VIGIE — construction des données du site de veille
# =============================================================================
#  1. Récupère les flux RSS/Atom de config/sources.json, le catalogue CISA KEV
#     et les CVE critiques de la NVD.
#  2. Évalue la criticité (CVSS ou mots-clés) et attribue des thèmes
#     (config/themes.json).
#  3. Fusionne avec l'historique (data/archive.json) pour garder une mémoire
#     de la veille au-delà de ce que les flux exposent.
#  4. Convertit les fiches Markdown (fiches/*.md) en HTML.
#  5. Écrit data/veille.js, data/fiches.js (chargés par la page) et feed.xml
#     (flux RSS du site).
#
#  Bibliothèque standard Python uniquement.
#  Usage : python scripts/build.py [--offline] [--drafts]
#    --offline : ne télécharge rien, reconstruit depuis l'archive et les fiches
#    --drafts  : publie aussi les fiches marquées « draft: true »
# =============================================================================

import hashlib
import html
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime, parsedate_to_datetime
from xml.etree import ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONF = os.path.join(ROOT, "config")
DATA = os.path.join(ROOT, "data")
FICHES = os.path.join(ROOT, "fiches")

TIMEOUT = 25
UA = "Mozilla/5.0 (compatible; VIGIE-veille/1.0)"
NOW = datetime.now(timezone.utc)


def load_json(name):
    with open(os.path.join(CONF, name), encoding="utf-8") as fh:
        return json.load(fh)


SITE = load_json("site.json")
SOURCES = load_json("sources.json")
THEMES = load_json("themes.json")["themes"]
AGENDA = load_json("agenda.json")["events"]

for th in THEMES:
    th["_re"] = re.compile(th["pattern"], re.I) if th.get("pattern") else None
    th["_re_cs"] = re.compile(th["pattern_cs"]) if th.get("pattern_cs") else None

# --- Texte -------------------------------------------------------------------
TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")


def clean_text(raw, limit=280):
    if not raw:
        return ""
    txt = html.unescape(TAG_RE.sub(" ", raw))
    txt = WS_RE.sub(" ", txt).strip()
    return txt[:limit].rstrip() + "…" if len(txt) > limit else txt


def parse_date(raw):
    if not raw:
        return None
    raw = raw.strip()
    try:
        d = parsedate_to_datetime(raw)
    except (TypeError, ValueError, IndexError):
        try:
            d = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)


def item_id(link, title):
    return hashlib.sha1((link or title or "").strip().encode("utf-8")).hexdigest()[:16]


# --- Criticité ---------------------------------------------------------------
CVSS_RES = (re.compile(r"cvss[^0-9]{0,14}(\d{1,2}(?:\.\d)?)", re.I),
            re.compile(r"(\d{1,2}(?:\.\d)?)\s*(?:/\s*10\s*)?cvss", re.I))
CRIT_KW = ("zero-day", "zero day", "0-day", "jour zéro", "activement exploit",
           "actively exploited", "exploited in the wild", "wormable",
           "vulnérabilité critique", "faille critique", "critical vulnerability",
           "critical flaw", "severity: critical")
HIGH_KW = ("remote code execution", "exécution de code arbitraire à distance",
           "exécution de code à distance", "high severity", "privilege escalation",
           "élévation de privilèges", "unauthenticated", "non authentifié", "pre-auth")


def cvss_to_sev(score):
    if score is None:
        return None
    return "crit" if score >= 9 else "high" if score >= 7 else "med" if score >= 4 else "low"


def extract_cvss(text):
    best = None
    for rx in CVSS_RES:
        for m in rx.finditer(text or ""):
            try:
                v = float(m.group(1))
            except ValueError:
                continue
            if 0 <= v <= 10:
                best = v if best is None else max(best, v)
    return best


def keyword_sev(text, kind):
    t = (text or "").lower()
    if any(k in t for k in CRIT_KW):
        return "crit"
    if kind in ("alerte", "kev"):
        return "high"
    if any(k in t for k in HIGH_KW):
        return "high"
    return None


def themes_for(text, group):
    out = []
    for th in THEMES:
        if group in th.get("groups", []):
            out.append(th["id"])
            continue
        if (th["_re"] and th["_re"].search(text)) or (th["_re_cs"] and th["_re_cs"].search(text)):
            out.append(th["id"])
    return out


def enrich(it):
    text = it["title"] + " " + it.get("summary", "")
    if it.get("cvss") is None:
        it["cvss"] = extract_cvss(text)
    it["sev"] = cvss_to_sev(it["cvss"]) or keyword_sev(text, it["kind"])
    themes = themes_for(text, it.get("group", ""))
    if it["kind"] == "kev" and "exploit" not in themes:
        themes.append("exploit")
    if it["kind"] in ("kev", "cve") and "vuln" not in themes:
        themes.append("vuln")
    it["themes"] = themes
    return it


# --- Récupération --------------------------------------------------------------
def fetch(url, timeout=TIMEOUT):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, application/json, */*",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def localname(tag):
    return tag.rsplit("}", 1)[-1].lower()


def child_text(el, names):
    for c in el:
        if localname(c.tag) in names and (c.text or "").strip():
            return c.text.strip()
    return ""


def atom_link(el):
    href = ""
    for c in el:
        if localname(c.tag) == "link" and c.get("href"):
            if c.get("rel", "alternate") == "alternate":
                return c.get("href")
            href = href or c.get("href")
    return href


def parse_feed(raw, src):
    root = ET.fromstring(raw)
    req = re.compile(src["require"], re.I) if src.get("require") else None
    items = []
    for e in root.iter():
        if localname(e.tag) not in ("item", "entry"):
            continue
        title = clean_text(child_text(e, {"title"}), 200) or "(sans titre)"
        link = (child_text(e, {"link"}) or atom_link(e)).strip()
        body = child_text(e, {"encoded", "content", "description", "summary"})
        if req and not req.search(title + " " + clean_text(body, 20000)):
            continue
        dt = parse_date(child_text(e, {"pubdate", "published", "updated", "date"}))
        items.append({
            "id": item_id(link, title), "title": title, "link": link,
            "summary": clean_text(body), "date": dt.isoformat() if dt else None,
            "source": src["name"], "kind": src["kind"], "cote": src["cote"],
            "group": src.get("group", ""), "cvss": None,
        })
    items.sort(key=lambda x: x["date"] or "", reverse=True)
    return items[: src.get("max", SITE.get("per_source", 25))]


def fetch_kev(cfg):
    data = json.loads(fetch(cfg["url"], timeout=60).decode("utf-8"))
    since = (NOW - timedelta(days=cfg.get("days", 30))).date().isoformat()
    out = []
    for v in data.get("vulnerabilities", []):
        if v.get("dateAdded", "") < since:
            continue
        cve = v.get("cveID", "")
        title = f"{cve} — {v.get('vendorProject', '')} {v.get('product', '')} : {v.get('vulnerabilityName', '')}".strip()
        summary = v.get("shortDescription", "")
        if v.get("knownRansomwareCampaignUse") == "Known":
            summary += " Utilisée dans des campagnes de rançongiciel."
        link = "https://nvd.nist.gov/vuln/detail/" + cve
        dt = parse_date(v.get("dateAdded"))
        out.append({
            "id": item_id(link + "#kev", title), "title": clean_text(title, 200), "link": link,
            "summary": clean_text(summary), "date": dt.isoformat() if dt else None,
            "source": cfg["name"], "kind": "kev", "cote": cfg["cote"],
            "group": cfg.get("group", ""), "cvss": None,
            "extra": {"due": v.get("dueDate"), "ransomware": v.get("knownRansomwareCampaignUse") == "Known"},
        })
    out.sort(key=lambda x: x["date"] or "", reverse=True)
    return out


def fetch_nvd(cfg):
    end, start = NOW, NOW - timedelta(days=cfg.get("days", 7))
    fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000")
    out = {}
    for sev in cfg.get("severities", ["CRITICAL"]):
        url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity=" + sev +
               "&pubStartDate=" + fmt(start) + "&pubEndDate=" + fmt(end) +
               "&resultsPerPage=" + str(cfg.get("per_severity", 15)))
        data = json.loads(fetch(url, timeout=60).decode("utf-8"))
        for v in data.get("vulnerabilities", []):
            cve = v.get("cve", {})
            cid = cve.get("id")
            if not cid:
                continue
            best = None
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
                for m in cve.get("metrics", {}).get(key, []) or []:
                    try:
                        s = float(m["cvssData"]["baseScore"])
                        best = s if best is None else max(best, s)
                    except (KeyError, TypeError, ValueError):
                        pass
            desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            dt = parse_date(cve.get("published"))
            link = "https://nvd.nist.gov/vuln/detail/" + cid
            out[cid] = {
                "id": item_id(link, cid), "title": cid, "link": link,
                "summary": clean_text(desc), "date": dt.isoformat() if dt else None,
                "source": cfg["name"], "kind": "cve", "cote": cfg["cote"],
                "group": cfg.get("group", ""), "cvss": best,
            }
    return sorted(out.values(), key=lambda x: x["date"] or "", reverse=True)


# --- Markdown (sous-ensemble) --------------------------------------------------
def md_inline(s):
    s = html.escape(s, quote=False)
    codes = []

    def keep_code(m):
        codes.append("<code>" + m.group(1) + "</code>")
        return "\x00%d\x00" % (len(codes) - 1)

    s = re.sub(r"`([^`]+)`", keep_code, s)
    s = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+|[^)\s:]+)\)",
               lambda m: '<a href="%s" target="_blank" rel="noopener">%s</a>' % (html.escape(m.group(2)), m.group(1)), s)
    s = re.sub(r"(?<![\"'>=])(https?://[^\s<)]+)", r'<a href="\1" target="_blank" rel="noopener">\1</a>', s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"(?<![\w*])\*([^*\s][^*]*)\*(?!\w)", r"<em>\1</em>", s)
    s = re.sub(r"(?<![\w_])_([^_\s][^_]*)_(?![\w_])", r"<em>\1</em>", s)
    return re.sub(r"\x00(\d+)\x00", lambda m: codes[int(m.group(1))], s)


def md_to_html(text):
    text = re.sub(r"<!--.*?-->", "", text, flags=re.S)   # commentaires de rédaction : jamais publiés
    lines = text.replace("\r\n", "\n").split("\n")
    out, i, n = [], 0, len(lines)
    para = []

    def flush():
        if para:
            out.append("<p>" + md_inline(" ".join(para)) + "</p>")
            para.clear()

    while i < n:
        ln = lines[i]
        st = ln.strip()
        if st.startswith("```"):
            flush()
            lang = st[3:].strip()
            buf = []
            i += 1
            while i < n and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            out.append('<pre><code class="lang-%s">%s</code></pre>' % (html.escape(lang), html.escape("\n".join(buf))))
            i += 1
            continue
        if not st:
            flush(); i += 1; continue
        m = re.match(r"^(#{1,6})\s+(.*)$", st)
        if m:
            flush()
            lvl = min(len(m.group(1)) + 1, 6)   # le titre de page est le h1
            slug = re.sub(r"[^\w]+", "-", m.group(2).lower()).strip("-")
            out.append('<h%d id="%s">%s</h%d>' % (lvl, slug, md_inline(m.group(2)), lvl))
            i += 1; continue
        if re.match(r"^(-{3,}|\*{3,})$", st):
            flush(); out.append("<hr>"); i += 1; continue
        if st.startswith(">"):
            flush()
            buf = []
            while i < n and lines[i].strip().startswith(">"):
                buf.append(lines[i].strip()[1:].strip())
                i += 1
            out.append("<blockquote>" + md_to_html("\n".join(buf)) + "</blockquote>")
            continue
        if st.startswith("|") and i + 1 < n and re.match(r"^\|?\s*:?-{2,}", lines[i + 1].strip()):
            flush()
            cells = lambda r: [c.strip() for c in r.strip().strip("|").split("|")]
            head = cells(st)
            i += 2
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                rows.append(cells(lines[i]))
                i += 1
            t = ['<div class="table-wrap"><table><thead><tr>']
            t += ["<th>%s</th>" % md_inline(c) for c in head]
            t.append("</tr></thead><tbody>")
            for r in rows:
                t.append("<tr>" + "".join("<td>%s</td>" % md_inline(c) for c in r) + "</tr>")
            t.append("</tbody></table></div>")
            out.append("".join(t))
            continue
        m = re.match(r"^([-*]|\d+[.)])\s+(.*)$", st)
        if m:
            flush()
            ordered = m.group(1)[0].isdigit()
            items = []
            while i < n:
                s2 = lines[i].strip()
                m2 = re.match(r"^([-*]|\d+[.)])\s+(.*)$", s2)
                if m2:
                    items.append(m2.group(2))
                elif s2 and items and lines[i].startswith(("  ", "\t")):
                    items[-1] += " " + s2
                else:
                    break
                i += 1
            tag = "ol" if ordered else "ul"
            lis = []
            for it in items:
                cb = re.match(r"^\[( |x|X)\]\s+(.*)$", it)
                if cb:
                    lis.append('<li class="task"><input type="checkbox" disabled%s> %s</li>' % (" checked" if cb.group(1) != " " else "", md_inline(cb.group(2))))
                else:
                    lis.append("<li>" + md_inline(it) + "</li>")
            out.append("<%s>%s</%s>" % (tag, "".join(lis), tag))
            continue
        para.append(st)
        i += 1
    flush()
    return "\n".join(out)


def parse_fiche(path):
    with open(path, encoding="utf-8") as fh:
        raw = fh.read()
    meta, body = {}, raw
    m = re.match(r"^---\n(.*?)\n---\n(.*)$", raw, re.S)
    if m:
        body = m.group(2)
        for ln in m.group(1).split("\n"):
            if ":" in ln:
                k, v = ln.split(":", 1)
                v = v.strip().strip('"')
                if v.startswith("[") and v.endswith("]"):
                    v = [x.strip().strip('"') for x in v[1:-1].split(",") if x.strip()]
                elif v.lower() in ("true", "false"):
                    v = v.lower() == "true"
                meta[k.strip()] = v
    slug = os.path.splitext(os.path.basename(path))[0]
    title = meta.get("title")
    if not title:
        h = re.search(r"^#\s+(.+)$", body, re.M)
        title = h.group(1) if h else slug
    body = re.sub(r"^#\s+.+\n", "", body, count=1, flags=re.M) if not meta.get("title") else body
    return {
        "slug": slug, "title": title, "date": meta.get("date", slug[:10]),
        "themes": meta.get("themes", []) if isinstance(meta.get("themes"), list) else [meta.get("themes")],
        "cote": meta.get("cote", ""), "criticite": meta.get("criticite", ""),
        "summary": meta.get("summary", ""), "sources": meta.get("sources", []),
        "draft": bool(meta.get("draft", False)), "html": md_to_html(body),
    }


# --- Synthèses hebdomadaires ---------------------------------------------------
SEV_RANK = {"crit": 3, "high": 2, "med": 1, "low": 0}


def weekly(items, weeks=12):
    buckets = {}
    for it in items:
        if not it.get("date"):
            continue
        d = datetime.fromisoformat(it["date"])
        y, w, _ = d.isocalendar()
        buckets.setdefault((y, w), []).append(it)
    out = []
    for (y, w) in sorted(buckets, reverse=True)[:weeks]:
        lst = buckets[(y, w)]
        monday = datetime.fromisocalendar(y, w, 1).date()
        counts = {}
        for it in lst:
            for t in it["themes"]:
                counts[t] = counts.get(t, 0) + 1
        top = sorted(lst, key=lambda x: ("exploit" in x["themes"], SEV_RANK.get(x.get("sev"), -1), x.get("cvss") or 0), reverse=True)
        top = [x["id"] for x in top if x.get("sev") in ("crit", "high") or "exploit" in x["themes"]][:12]
        out.append({
            "key": "%d-S%02d" % (y, w), "start": monday.isoformat(),
            "end": (monday + timedelta(days=6)).isoformat(), "total": len(lst),
            "severe": sum(1 for x in lst if x.get("sev") in ("crit", "high")),
            "themes": counts, "top": top,
        })
    return out


# --- Flux RSS du site ------------------------------------------------------------
def write_site_feed(fiches, items):
    base = SITE.get("site_url", "").rstrip("/")
    rss = ET.Element("rss", version="2.0")
    ch = ET.SubElement(rss, "channel")
    ET.SubElement(ch, "title").text = SITE["name"] + " — " + SITE["tagline"]
    ET.SubElement(ch, "link").text = base or "./"
    ET.SubElement(ch, "description").text = SITE["description"]
    ET.SubElement(ch, "language").text = SITE.get("language", "fr")
    ET.SubElement(ch, "lastBuildDate").text = format_datetime(NOW)
    entries = []
    for f in fiches:
        d = parse_date(f["date"]) or NOW
        entries.append((d, "Fiche : " + f["title"], (base + "/" if base else "") + "#/fiche/" + f["slug"], f["summary"]))
    for it in items:
        if it.get("sev") == "crit" or "exploit" in it["themes"]:
            entries.append((parse_date(it["date"]) or NOW, "[%s] %s" % (it["source"], it["title"]), it["link"], it["summary"]))
    for d, title, link, desc in sorted(entries, key=lambda x: x[0], reverse=True)[:60]:
        e = ET.SubElement(ch, "item")
        ET.SubElement(e, "title").text = title
        ET.SubElement(e, "link").text = link
        ET.SubElement(e, "guid", isPermaLink="false").text = hashlib.sha1((link + title).encode()).hexdigest()
        ET.SubElement(e, "pubDate").text = format_datetime(d)
        ET.SubElement(e, "description").text = desc
    ET.ElementTree(rss).write(os.path.join(ROOT, "feed.xml"), encoding="utf-8", xml_declaration=True)


def write_js(path, var, payload):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("/* Généré par scripts/build.py — ne pas modifier à la main */\n")
        fh.write("window.%s = %s;\n" % (var, json.dumps(payload, ensure_ascii=False, separators=(",", ":"))))


# --- Principal ---------------------------------------------------------------------
def main():
    offline = "--offline" in sys.argv
    drafts = "--drafts" in sys.argv
    os.makedirs(DATA, exist_ok=True)

    archive_path = os.path.join(DATA, "archive.json")
    archive = {}
    if os.path.exists(archive_path):
        with open(archive_path, encoding="utf-8") as fh:
            archive = {x["id"]: x for x in json.load(fh)}

    status, fresh = [], []
    jobs = [(s, lambda s=s: parse_feed(fetch(s["url"]), s)) for s in SOURCES["feeds"]]
    if SOURCES.get("kev"):
        jobs.append((SOURCES["kev"], lambda: fetch_kev(SOURCES["kev"])))
    if SOURCES.get("nvd"):
        nvd = dict(SOURCES["nvd"], url="https://nvd.nist.gov/")
        jobs.append((nvd, lambda: fetch_nvd(SOURCES["nvd"])))

    for src, job in jobs:
        st = {"name": src["name"], "url": src.get("url", ""), "kind": src["kind"],
              "cote": src["cote"], "group": src.get("group", ""), "ok": None, "count": 0}
        if not offline:
            try:
                got = job()
                fresh.extend(got)
                st["ok"], st["count"] = True, len(got)
                print("[ok]   %-38s %3d" % (src["name"], len(got)))
            except Exception as exc:   # une source en panne n'arrête jamais la construction
                st["ok"], st["error"] = False, str(exc)[:200]
                print("[warn] %-38s %s" % (src["name"], exc), file=sys.stderr)
        status.append(st)

    now_iso = NOW.isoformat(timespec="seconds")
    for it in fresh:
        enrich(it)
        old = archive.get(it["id"])
        it["first_seen"] = old.get("first_seen", now_iso) if old else now_iso
        if not it.get("date"):
            it["date"] = it["first_seen"]
        archive[it["id"]] = it

    # Ré-applique thèmes et criticité aux entrées archivées (si les règles ont changé)
    for it in archive.values():
        enrich(it)

    limit = (NOW - timedelta(days=SITE.get("retention_days", 120))).isoformat()
    kept = sorted((x for x in archive.values() if (x.get("date") or "") >= limit),
                  key=lambda x: x.get("date") or "", reverse=True)
    with open(archive_path, "w", encoding="utf-8") as fh:
        json.dump(kept, fh, ensure_ascii=False, indent=0)

    recent_limit = (NOW - timedelta(days=SITE.get("recent_days", 30))).isoformat()
    recent = [x for x in kept if (x.get("date") or "") >= recent_limit]

    fiches = []
    if os.path.isdir(FICHES):
        for fn in sorted(os.listdir(FICHES), reverse=True):
            if fn.endswith(".md") and not fn.startswith("_"):
                f = parse_fiche(os.path.join(FICHES, fn))
                if f["draft"] and not drafts:
                    continue
                fiches.append(f)

    public_site = {k: SITE.get(k, "") for k in ("name", "tagline", "description", "repo", "site_url", "recent_days")}
    write_js(os.path.join(DATA, "veille.js"), "VIGIE_DATA", {
        "updated": now_iso if not offline else (max((s.get("first_seen", "") for s in kept), default=now_iso)),
        "site": public_site,
        "themes": [{k: t[k] for k in ("id", "label", "icon", "color")} for t in THEMES],
        "sources": status,
        "items": recent,
        "weeks": weekly(kept),
        "agenda": AGENDA,
        "stats": {"archive": len(kept), "recent": len(recent)},
    })
    write_js(os.path.join(DATA, "fiches.js"), "VIGIE_FICHES", fiches)
    write_site_feed(fiches, recent)

    ok = sum(1 for s in status if s["ok"])
    print("\n%d entrées récentes, %d en archive, %d fiches, sources : %s" % (
        len(recent), len(kept), len(fiches), "hors ligne" if offline else "%d/%d OK" % (ok, len(status))))


if __name__ == "__main__":
    main()
