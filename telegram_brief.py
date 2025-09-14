import os, re, time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import feedparser  # pip install feedparser
except Exception:
    feedparser = None

# --------- Config from ENV (defaults stay conservative) ----------
LOCAL_TZ = os.getenv("LOCAL_TZ", "Europe/Riga")

STRICT_0830 = os.getenv("STRICT_0830", "0") == "1"
STRICT_0830_TOL_MIN = int(os.getenv("STRICT_0830_TOL_MIN", "7"))
SKIP_WEEKENDS = os.getenv("SKIP_WEEKENDS", "0") == "1"

KEV_WINDOW_DAYS = int(os.getenv("KEV_WINDOW_DAYS", "3"))
EPSS_MIN = float(os.getenv("EPSS_MIN", "0.7"))
EPSS_LIMIT = int(os.getenv("EPSS_LIMIT", "10"))

# How many items to show
HEADLINES_TOTAL = int(os.getenv("HEADLINES_TOTAL", "6"))
VENDOR_TOTAL = int(os.getenv("VENDOR_TOTAL", "10"))
FEED_MAX_PER_SOURCE = int(os.getenv("FEED_MAX_PER_SOURCE", "6"))

# Limit news by recency
HEADLINES_WINDOW_DAYS = int(os.getenv("HEADLINES_WINDOW_DAYS", "3"))
VENDOR_WINDOW_DAYS = int(os.getenv("VENDOR_WINDOW_DAYS", "3"))

# Keyword ranking (comma-separated)
def _csv_env(name, default):
    return [s.strip().lower() for s in os.getenv(name, default).split(",") if s.strip()]

HEADLINE_KEYWORDS = _csv_env(
    "HEADLINE_KEYWORDS",
    "0-day,zero-day,actively exploited,exploited,exploit,weaponized,kev,cisa,patch tuesday,ransomware,supply chain"
)
STACK_KEYWORDS = _csv_env(
    "STACK_KEYWORDS",
    "microsoft,cisco,fortinet,ivanti,citrix,gitlab,jenkins,atlassian,confluence,vmware,exchange,sharepoint,globalprotect,pan-os,big-ip,f5,moveit,screenconnect,sonicwall,cloudflare,aws,azure,gcp,okta,nginx,apache"
)

# Feeds supplied from YAML (newline or comma separated). If empty, we fallback to minimal defaults.
def _list_from_env(name, defaults):
    raw = os.getenv(name, "").strip()
    parts = []
    if raw:
        # support newline-separated block or CSV
        for line in raw.splitlines():
            for p in line.split(","):
                p = p.strip()
                if p.startswith("http"):
                    parts.append(p)
    if not parts:
        parts = defaults[:]  # copy
    return parts

DEFAULT_HEADLINES = [
    "https://www.bleepingcomputer.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://therecord.media/feed",
    "https://www.microsoft.com/en-us/security/blog/feed/",
    "https://blog.google/threat-analysis-group/rss/",
    "https://aws.amazon.com/blogs/security/feed/",
]
HEADLINE_FEEDS = _list_from_env("HEADLINE_FEEDS", DEFAULT_HEADLINES)

# VENDOR_FEEDS: leave empty by default; you’ll provide in YAML
VENDOR_FEEDS = _list_from_env("VENDOR_FEEDS", [])

TELEGRAM_MAX = 3900  # keep under 4096

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = f"https://api.first.org/data/v1/epss?epss-gt={EPSS_MIN}&order=!epss&limit=1000"

# ----------------------------- HTTP session -----------------------------------
def make_session():
    s = requests.Session()
    r = Retry(
        total=3, backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    s.mount("https://", HTTPAdapter(max_retries=r))
    s.headers.update({"User-Agent": "DevSecOpsBrief/Pro/2.1 (+github-actions)"})
    return s

SESSION = make_session()

# ------------------------------- Helpers --------------------------------------
def now_local():
    return datetime.now(ZoneInfo(LOCAL_TZ))

def within_0830_guard():
    if not STRICT_0830:
        return True
    n = now_local()
    if SKIP_WEEKENDS and n.weekday() >= 5:
        return False
    return (n.hour == 8) and (abs(n.minute - 30) <= STRICT_0830_TOL_MIN)

def split_chunks(text: str, limit=TELEGRAM_MAX):
    if len(text) <= limit:
        return [text]
    parts, buf, cur = [], [], 0
    for ln in text.split("\n"):
        ln_len = len(ln) + 1
        if cur + ln_len > limit and buf:
            parts.append("\n".join(buf))
            buf, cur = [], 0
        buf.append(ln)
        cur += ln_len
    if buf:
        parts.append("\n".join(buf))
    return parts

def esc(s: str) -> str:
    return (s or "").replace("\r", "").strip()

def keyword_hit(s: str, keywords):
    t = (s or "").lower()
    return any(k in t for k in keywords)

def _age_cut(ts, window_days):
    cutoff = time.time() - window_days * 86400
    return ts >= cutoff

# ------------------------------- Collectors -----------------------------------
def get_kev(window_days=KEV_WINDOW_DAYS):
    since = (datetime.now(timezone.utc) - timedelta(days=window_days)).date().isoformat()
    r = SESSION.get(KEV_URL, timeout=30)
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities", [])
    out = []
    for v in vulns:
        if (v.get("dateAdded") or "") >= since:
            out.append({
                "cve": v.get("cveID"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "desc": (v.get("shortDescription") or "").strip(),
                "dateAdded": v.get("dateAdded"),
            })
    out.sort(key=lambda x: (x.get("dateAdded") or "", x.get("cve") or ""), reverse=True)
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
        if epss >= EPSS_MIN:
            out.append({"cve": d.get("cve"), "epss": epss, "pct": pct})
    out.sort(key=lambda x: x["epss"], reverse=True)
    return out

def parse_feeds(urls, window_days, total_limit, max_per_source=FEED_MAX_PER_SOURCE, boost_keywords=None):
    if not feedparser:
        return []
    items = []
    for url in urls:
        try:
            f = feedparser.parse(url)
            cnt = 0
            for e in f.entries:
                if cnt >= max_per_source:
                    break
                # timestamp best-effort
                ts = 0
                if getattr(e, "published_parsed", None):
                    ts = time.mktime(e.published_parsed)
                elif getattr(e, "updated_parsed", None):
                    ts = time.mktime(e.updated_parsed)
                if ts and not _age_cut(ts, window_days):
                    continue
                items.append({
                    "title": esc(getattr(e, "title", "")),
                    "link": esc(getattr(e, "link", "")),
                    "ts": ts or 0,
                })
                cnt += 1
        except Exception:
            continue

    # score by recency + keyword boost
    def score(it):
        bonus = 0
        if boost_keywords and keyword_hit(it["title"], boost_keywords):
            bonus = 6 * 3600
        return (it["ts"] or 0) + bonus

    items.sort(key=score, reverse=True)

    # de-dupe by normalized title
    seen, uniq = set(), []
    for it in items:
        key = it["title"].lower()
        if key not in seen:
            seen.add(key)
            uniq.append(it)
        if len(uniq) >= total_limit:
            break
    return uniq

# ------------------------------ Brief builder ---------------------------------
def build_brief():
    kev = get_kev()
    epss = get_epss()
    kev_set = {k["cve"] for k in kev}
    epss_only = [e for e in epss if e["cve"] not in kev_set][:EPSS_LIMIT]

    headlines = parse_feeds(HEADLINE_FEEDS, HEADLINES_WINDOW_DAYS, HEADLINES_TOTAL,
                            max_per_source=FEED_MAX_PER_SOURCE, boost_keywords=HEADLINE_KEYWORDS)
    vendor_news = parse_feeds(VENDOR_FEEDS, VENDOR_WINDOW_DAYS, VENDOR_TOTAL,
                              max_per_source=FEED_MAX_PER_SOURCE, boost_keywords=STACK_KEYWORDS)

    lines = []
    lines.append(f"Daily DevSecOps brief — {now_local().strftime('%Y-%m-%d %H:%M')} {LOCAL_TZ}")

    # KEV
    lines.append("")
    lines.append(f"Known Exploited (last {KEV_WINDOW_DAYS}d):")
    if kev:
        for k in kev[:12]:
            vendor = esc(k.get("vendor") or "")
            product = esc(k.get("product") or "")
            desc = esc(k.get("desc") or "")
            stack = " | YOUR-STACK" if keyword_hit(f"{vendor} {product} {desc}", STACK_KEYWORDS) else ""
            lines.append(f"- {k['cve']} — {vendor}/{product}: {desc}{stack} | Action: Patch/mitigate, add detection.")
    else:
        lines.append("- (No new KEV entries in window)")

    # EPSS
    lines.append("")
    lines.append(f"High-likelihood CVEs (EPSS ≥ {EPSS_MIN:.2f}, not in KEV):")
    if epss_only:
        for e in epss_only:
            pct = int(round((e.get("pct") or 0) * 100))
            lines.append(f"- {e['cve']} — EPSS {e['epss']:.2f} (Pctl {pct}) | Action: Prioritize remediation/detection.")
    else:
        lines.append("- (No EPSS candidates after KEV de-dup)")

    # Vendor advisories (from your curated feeds)
    lines.append("")
    lines.append(f"Vendor advisories (last {VENDOR_WINDOW_DAYS}d):")
    if vendor_news:
        for it in vendor_news:
            lines.append(f"- {it['title']} — {it['link']}")
    else:
        lines.append("- (No vendor advisories in window or no feeds configured)")

    # Headlines
    lines.append("")
    lines.append(f"Security headlines (last {HEADLINES_WINDOW_DAYS}d):")
    if headlines:
        for it in headlines:
            lines.append(f"- {it['title']} — {it['link']}")
    else:
        lines.append("- (No headlines available)")

    # Controls of the day
    lines.append("")
    lines.append("Controls today:")
    lines.append("• Fast-track KEV patching; restrict exposed edge apps until patched.")
    lines.append("• Validate internet exposure: VPNs/gateways, Exchange/OWA, Confluence, Git* servers.")
    lines.append("• Detections: auth anomalies, webshell writes, sudden service restarts.")
    lines.append("• Backups: confirm recent, offline/immutable for RCE/priv-esc impacted systems.")

    msg = "\n".join(lines)
    return msg[:TELEGRAM_MAX]

# ------------------------------ Telegram sender -------------------------------
def send_telegram(text: str):
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_ids = []
    if os.getenv("TELEGRAM_CHAT_IDS"):
        chat_ids = [c.strip() for c in os.getenv("TELEGRAM_CHAT_IDS").split(",") if c.strip()]
    elif os.getenv("TELEGRAM_CHAT_ID"):
        chat_ids = [os.getenv("TELEGRAM_CHAT_ID")]
    else:
        raise RuntimeError("No TELEGRAM_CHAT_ID or TELEGRAM_CHAT_IDS provided.")

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    chunks = split_chunks(text)

    for cid in chat_ids:
        for i, chunk in enumerate(chunks, 1):
            r = SESSION.post(url, data={"chat_id": cid, "text": chunk, "disable_web_page_preview": True}, timeout=30)
            if r.status_code >= 400:
                print(f"[telegram] ERROR {r.status_code} {r.text}")
            r.raise_for_status()
            time.sleep(0.3)

# ----------------------------------- Main -------------------------------------
if __name__ == "__main__":
    if not within_0830_guard():
        print("[guard] Not within 08:30 window; exiting.")
        raise SystemExit(0)

    brief = build_brief()
    send_telegram(brief)
