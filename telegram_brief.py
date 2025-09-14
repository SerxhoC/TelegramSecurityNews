import os, re, html, time, math, json
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import feedparser  # pip install feedparser
except Exception:
    feedparser = None

###############################################################################
# Config (env overrides)
###############################################################################
LOCAL_TZ = os.getenv("LOCAL_TZ", "Europe/Riga")
STRICT_0830 = os.getenv("STRICT_0830", "0") == "1"   # only send around 08:30 local if true
STRICT_0830_TOL_MIN = int(os.getenv("STRICT_0830_TOL_MIN", "6"))  # +/- window minutes
SKIP_WEEKENDS = os.getenv("SKIP_WEEKENDS", "0") == "1"

KEV_WINDOW_DAYS = int(os.getenv("KEV_WINDOW_DAYS", "3"))   # KEV lookback
EPSS_MIN = float(os.getenv("EPSS_MIN", "0.7"))
EPSS_LIMIT = int(os.getenv("EPSS_LIMIT", "12"))

FEED_COUNT = int(os.getenv("FEED_COUNT", "4"))
HEADLINE_KEYWORDS = [s.strip() for s in os.getenv(
    "HEADLINE_KEYWORDS",
    "0-day,zero-day,actively exploited,exploited,exploit,weaponized,keV,cisa,patch tuesday,ransomware,supply chain"
).split(",") if s.strip()]

# Highlight stack-relevant tech/vendors (comma-separated, case-insensitive)
STACK_KEYWORDS = [s.strip() for s in os.getenv(
    "STACK_KEYWORDS",
    "microsoft,cisco,fortinet,ivanti,citrix,gitlab,git,jenkins,atlassian,confluence,vmware,exchange,sharepoint,globalprotect,pan-os,big-ip,f5,moveit,screenconnect,sonicwall"
).split(",") if s.strip()]

# Multiple chat IDs supported: "12345,-10055555"
TELEGRAM_CHAT_IDS = os.getenv("TELEGRAM_CHAT_IDS")  # optional; overrides TELEGRAM_CHAT_ID

TELEGRAM_PARSE_MODE = os.getenv("TELEGRAM_PARSE_MODE", "HTML")  # HTML or MarkdownV2
TELEGRAM_MAX = 3900  # keep below Telegram 4096 w/ some margin

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = f"https://api.first.org/data/v1/epss?epss-gt={EPSS_MIN}&order=!epss&limit=1000"
CIRCL_CVE_URL = "https://cve.circl.lu/api/cve/{}"

HEADLINE_FEEDS = [
    "https://www.bleepingcomputer.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://therecord.media/feed",
    "https://www.microsoft.com/en-us/security/blog/feed/",
    "https://blog.google/threat-analysis-group/rss/",
    "https://aws.amazon.com/blogs/security/feed/",
]

###############################################################################
# HTTP session with retries
###############################################################################
def make_session():
    s = requests.Session()
    retries = Retry(
        total=3, backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    s.headers.update({"User-Agent": "DevSecOpsBrief/2.0 (+github-actions)"})
    s.mount("https://", HTTPAdapter(max_retries=retries))
    return s

SESSION = make_session()

###############################################################################
# Helpers
###############################################################################
def now_local():
    return datetime.now(ZoneInfo(LOCAL_TZ))

def within_0830_guard():
    if not STRICT_0830:
        return True
    n = now_local()
    if SKIP_WEEKENDS and n.weekday() >= 5:
        return False
    return (n.hour == 8) and (abs(n.minute - 30) <= STRICT_0830_TOL_MIN)

def html_escape(s: str) -> str:
    return html.escape(s or "", quote=False)

def split_chunks(text: str, limit: int = TELEGRAM_MAX):
    """Split text into chunks respecting paragraph boundaries."""
    parts = []
    if len(text) <= limit:
        return [text]
    lines = text.split("\n")
    buf = []
    cur_len = 0
    for ln in lines:
        ln_len = len(ln) + 1
        if cur_len + ln_len > limit and buf:
            parts.append("\n".join(buf))
            buf, cur_len = [], 0
        buf.append(ln)
        cur_len += ln_len
    if buf:
        parts.append("\n".join(buf))
    return parts

def tag_flags(text: str):
    """Simple NLP-ish flags from description/summary."""
    t = (text or "").lower()
    flags = []
    patterns = [
        ("RCE", r"remote code execution|arbitrary code execution|code execution"),
        ("AUTH-BYPASS", r"authentication bypass|bypass authentication|unauthenticated"),
        ("PRIV-ESC", r"privilege escalation|elevation of privilege|eop"),
        ("SQLi", r"sql injection"),
        ("DESERIALIZATION", r"deserializ"),
        ("SSRF", r"\bssrf\b|server-side request forgery"),
        ("TRAVERSAL", r"path traversal|directory traversal"),
        ("XXE", r"\bxxe\b|xml external entity"),
        ("XSS", r"cross[- ]site scripting|\bxss\b"),
        ("LFI/RFI", r"local file inclusion|remote file inclusion|\b(rfi|lfi)\b"),
        ("INJECTION", r"injection"),
    ]
    for name, pat in patterns:
        if re.search(pat, t):
            flags.append(name)
    # Internet-exposed tech hints
    exposed = [
        "vpn","ssl vpn","gateway","reverse proxy","edge","exchange","owa","sharepoint",
        "confluence","jira","gitlab","jenkins","fortinet","pulse secure","globalprotect",
        "pan-os","big-ip","f5","netscaler","citrix","moveit","screenconnect","sonicwall"
    ]
    if any(w in t for w in exposed):
        flags.insert(0, "INTERNET-EXPOSED")
    return flags

def keyword_hit(s: str, keywords):
    t = (s or "").lower()
    return any(k in t for k in keywords)

###############################################################################
# Data collectors
###############################################################################
def get_kev(window_days=KEV_WINDOW_DAYS):
    since = (datetime.now(timezone.utc) - timedelta(days=window_days)).date().isoformat()
    r = SESSION.get(KEV_URL, timeout=30)
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities", [])
    out = []
    for v in vulns:
        if v.get("dateAdded", "") >= since:
            out.append({
                "cve": v.get("cveID"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "desc": (v.get("shortDescription") or "").strip(),
                "dateAdded": v.get("dateAdded"),
                "dueDate": v.get("dueDate"),
            })
    # Stable sort: newer first
    out.sort(key=lambda x: (x.get("dateAdded") or "", x["cve"]), reverse=True)
    return out

def get_epss():
    r = SESSION.get(EPSS_URL, timeout=30)
    r.raise_for_status()
    data = r.json().get("data", [])
    out = []
    for d in data:
        try:
            epss = float(d.get("epss", "0"))
            pct = float(d.get("percentile", "0"))
        except Exception:
            continue
        out.append({"cve": d.get("cve"), "epss": epss, "pct": pct})
    out.sort(key=lambda x: x["epss"], reverse=True)
    return out

def enrich_cve(cve_id: str):
    """Best-effort enrichment via CIRCL (CVSS, CWE, summary)."""
    try:
        r = SESSION.get(CIRCL_CVE_URL.format(cve_id), timeout=15)
        if r.status_code != 200:
            return {}
        j = r.json()
        # CIRCL can return {} or not found
        if not isinstance(j, dict) or "id" not in j:
            return {}
        cvss3 = None
        if isinstance(j.get("cvss3"), (int, float, str)):
            try:
                cvss3 = float(j["cvss3"])
            except Exception:
                cvss3 = None
        vector = j.get("cvss3_vector") or j.get("vectorString")
        cwe = j.get("cwe")
        summary = j.get("summary")
        refs = j.get("references", []) or []
        return {
            "cvss3": cvss3,
            "vector": vector,
            "cwe": cwe,
            "summary": summary,
            "ref1": refs[0] if refs else None
        }
    except Exception:
        return {}

def safe_top_headlines(n=FEED_COUNT):
    if not feedparser:
        return []
    items = []
    for url in HEADLINE_FEEDS:
        try:
            f = feedparser.parse(url)
            for e in f.entries[:6]:
                ts = 0
                if getattr(e, "published_parsed", None):
                    ts = time.mktime(e.published_parsed)
                elif getattr(e, "updated_parsed", None):
                    ts = time.mktime(e.updated_parsed)
                items.append({
                    "title": (e.title or "").strip(),
                    "link": e.link,
                    "ts": ts,
                })
        except Exception:
            continue
    # Score headlines by recency + keyword presence
    def score(it):
        base = it["ts"]
        bonus = 60 * 60 * 6 if keyword_hit(it["title"], HEADLINE_KEYWORDS) else 0
        return base + bonus
    items.sort(key=score, reverse=True)

    # de-dup by normalized title
    seen, uniq = set(), []
    for it in items:
        key = it["title"].lower()
        if key not in seen:
            seen.add(key)
            uniq.append(it)
        if len(uniq) >= n:
            break
    return uniq

###############################################################################
# Brief builder
###############################################################################
def build_brief():
    kev = get_kev()
    epss = get_epss()

    kev_set = {k["cve"] for k in kev}
    epss_only = [e for e in epss if e["cve"] not in kev_set][:EPSS_LIMIT]

    # Enrich KEV + EPSS-only with CVSS/CWE & flags
    def annotate(item, base_desc=None):
        cve = item["cve"]
        enrich = enrich_cve(cve)
        desc = enrich.get("summary") or base_desc or ""
        flags = tag_flags((desc or "") + " " + (base_desc or ""))
        sev = ""
        if enrich.get("cvss3") is not None:
            try:
                cv = float(enrich["cvss3"])
                if cv >= 9.0: sev = "CRITICAL"
                elif cv >= 7.0: sev = "HIGH"
                elif cv >= 4.0: sev = "MEDIUM"
                else: sev = "LOW"
            except Exception:
                pass
        item.update({
            "desc": desc or base_desc or "",
            "flags": flags,
            "cvss3": enrich.get("cvss3"),
            "severity": sev,
            "vector": enrich.get("vector"),
            "cwe": enrich.get("cwe"),
            "ref": enrich.get("ref1"),
        })
        return item

    kev = [annotate(dict(k), k.get("desc")) for k in kev]
    epss_only = [annotate(dict(e)) for e in epss_only]

    # Prioritize stack-relevant items to the top of each list
    def sort_key(item):
        w = 0
        base_text = " ".join([str(item.get("vendor","")), str(item.get("product","")), item.get("desc","")]).lower()
        if keyword_hit(base_text, STACK_KEYWORDS):
            w += 1000
        if "INTERNET-EXPOSED" in item.get("flags", []):
            w += 500
        if "RCE" in item.get("flags", []):
            w += 250
        if item.get("severity") == "CRITICAL":
            w += 200
        try:
            w += int((item.get("epss") or 0) * 100)  # 0..100
        except Exception:
            pass
        # newer KEV first
        w += 10 if item.get("dateAdded") else 0
        return -w

    kev.sort(key=sort_key)
    epss_only.sort(key=sort_key)

    hl = safe_top_headlines(FEED_COUNT)

    # Render HTML message
    lines = []
    lines.append("<b>Daily DevSecOps brief</b>")
    lines.append(f"<i>Local time: {html_escape(now_local().strftime('%Y-%m-%d %H:%M'))} ({LOCAL_TZ})</i>")

    # KEV
    lines.append("")
    lines.append(f"<b>Known Exploited (last {KEV_WINDOW_DAYS}d)</b>")
    if kev:
        for k in kev[:12]:
            tags = " ".join(f"[{t}]" for t in k.get("flags", []))
            sev = f" | CVSS {k['cvss3']:.1f} {k['severity']}" if k.get("cvss3") is not None else ""
            stack = " | <b>YOUR STACK</b>" if keyword_hit(" ".join([str(k.get("vendor","")), str(k.get("product","")), k.get("desc","")]), STACK_KEYWORDS) else ""
            ref = f" — <a href='{html_escape(k['ref'])}'>ref</a>" if k.get("ref") else ""
            base = f"- <b>{html_escape(k['cve'])}</b> — {html_escape(k.get('vendor',''))}/{html_escape(k.get('product',''))}: {html_escape(k.get('desc'))}"
            extra = f" | Action: Patch/mitigate, add detection{sev}{stack}{ref}"
            if tags:
                extra = f" {html_escape(tags)}{extra}"
            lines.append(base + extra)
    else:
        lines.append("- (No new KEV items in window)")

    # EPSS
    lines.append("")
    lines.append(f"<b>High-likelihood CVEs (EPSS ≥ {EPSS_MIN:.2f}, not in KEV)</b>")
    if epss_only:
        for e in epss_only:
            pct = int(round((e.get("pct") or 0) * 100))
            tags = " ".join(f"[{t}]" for t in e.get("flags", []))
            sev = f" | CVSS {e['cvss3']:.1f} {e['severity']}" if e.get("cvss3") is not None else ""
            ref = f" — <a href='{html_escape(e['ref'])}'>ref</a>" if e.get("ref") else ""
            hot = "🔥" if (e.get("epss") or 0) >= 0.9 else ""
            extra = f" | EPSS {e.get('epss',0):.2f} (Pctl {pct}){sev}"
            base = f"- {hot}<b>{html_escape(e['cve'])}</b>: {html_escape(e.get('desc',''))}"
            if tags:
                extra = f" {html_escape(tags)}{extra}"
            lines.append(base + extra + ref + " | Action: Prioritize remediation/detection.")
    else:
        lines.append("- (No EPSS candidates after de-duplication with KEV)")

    # Headlines
    lines.append("")
    lines.append("<b>Situational awareness</b>")
    if hl:
        for h in hl:
            title = html_escape(h["title"])
            link = html_escape(h["link"])
            lines.append(f"- <a href='{link}'>{title}</a>")
    else:
        lines.append("- (No headlines available)")

    # Add a compact “Controls to apply today”—generic & safe
    lines.append("")
    lines.append("<b>Controls to apply today</b>")
    lines.append("• Validate internet exposure for VPNs, gateways, and collaboration apps (Exchange/OWA, Confluence, GitLab, Jenkins).")
    lines.append("• Patch window: fast-track KEV items; temporarily restrict public access where feasible.")
    lines.append("• Detection: watch for suspicious auth, webshell drops, and device reboots/ha resets after patching.")
    lines.append("• Block: known bad IPs/domains from vendor advisories where available; monitor outbound to paste/file-sharing.")
    lines.append("• Backup: verify recent, offline/immutable copies for critical apps impacted by RCE/priv-esc vulns.")

    msg = "\n".join(lines)
    return msg

###############################################################################
# Telegram sender
###############################################################################
def send_telegram(text: str):
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_id_single = os.environ.get("TELEGRAM_CHAT_ID")
    chat_ids = []
    if TELEGRAM_CHAT_IDS:
        chat_ids = [c.strip() for c in TELEGRAM_CHAT_IDS.split(",") if c.strip()]
    elif chat_id_single:
        chat_ids = [chat_id_single]
    else:
        raise RuntimeError("No TELEGRAM_CHAT_ID or TELEGRAM_CHAT_IDS env provided.")

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payloads = []
    for chunk in split_chunks(text):
        payloads.append({
            "text": chunk,
            "parse_mode": TELEGRAM_PARSE_MODE,
            "disable_web_page_preview": True
        })

    results = []
    for cid in chat_ids:
        for p in payloads:
            data = {"chat_id": cid, **p}
            r = SESSION.post(url, data=data, timeout=30)
            r.raise_for_status()
            results.append(r.json())
            # small pause to avoid flood-limits if multiple chunks
            time.sleep(0.5)
    return results

###############################################################################
# Main
###############################################################################
if __name__ == "__main__":
    if not within_0830_guard():
        # Quiet exit if guard is enabled and not the window we want
        # (Use dual-CRON 05:30/06:30 UTC so it always lands on 08:30 Riga year-round)
        raise SystemExit(0)

    brief = build_brief()
    send_telegram(brief)
