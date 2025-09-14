import os, re, time, html
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import feedparser  # pip install feedparser
except Exception:
    feedparser = None

# ----------------------------- Config (env) -----------------------------------
LOCAL_TZ = os.getenv("LOCAL_TZ", "Europe/Riga")

# Schedule guard (off by default). Turn on with STRICT_0830=1 if you add dual-cron.
STRICT_0830 = os.getenv("STRICT_0830", "0") == "1"         # send only ~08:30 local
STRICT_0830_TOL_MIN = int(os.getenv("STRICT_0830_TOL_MIN", "7"))  # +/- minutes
SKIP_WEEKENDS = os.getenv("SKIP_WEEKENDS", "0") == "1"

# Data knobs
KEV_WINDOW_DAYS = int(os.getenv("KEV_WINDOW_DAYS", "3"))    # lookback for KEV
EPSS_MIN = float(os.getenv("EPSS_MIN", "0.7"))              # min EPSS
EPSS_LIMIT = int(os.getenv("EPSS_LIMIT", "10"))             # max EPSS (post de-dup)
FEED_COUNT = int(os.getenv("FEED_COUNT", "4"))              # # of headlines

# Headlines scoring keywords (lowercase contains match)
HEADLINE_KEYWORDS = [s.strip() for s in os.getenv(
    "HEADLINE_KEYWORDS",
    "0-day,zero-day,actively exploited,exploited,exploit,weaponized,kev,cisa,patch tuesday,ransomware,supply chain"
).split(",") if s.strip()]

# Stack-relevant words to highlight (lowercase contains match)
STACK_KEYWORDS = [s.strip() for s in os.getenv(
    "STACK_KEYWORDS",
    "microsoft,cisco,fortinet,ivanti,citrix,gitlab,jenkins,atlassian,confluence,vmware,exchange,sharepoint,globalprotect,pan-os,big-ip,f5,moveit,screenconnect,sonicwall,cloudflare,aws,azure,gcp,okta,git,nginx,apache"
).split(",") if s.strip()]

# Telegram
TELEGRAM_CHAT_IDS = os.getenv("TELEGRAM_CHAT_IDS")  # optional; overrides TELEGRAM_CHAT_ID
TELEGRAM_MAX = 3900  # safe under Telegram’s 4096 limit

# ----------------------------- Sources ----------------------------------------
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# we’ll still filter client-side, but server-side filter helps
EPSS_URL = f"https://api.first.org/data/v1/epss?epss-gt={EPSS_MIN}&order=!epss&limit=1000"

HEADLINE_FEEDS = [
    "https://www.bleepingcomputer.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://therecord.media/feed",
    "https://www.microsoft.com/en-us/security/blog/feed/",
    "https://blog.google/threat-analysis-group/rss/",
    "https://aws.amazon.com/blogs/security/feed/",
]

# ----------------------------- HTTP session -----------------------------------
def make_session():
    s = requests.Session()
    r = Retry(
        total=3, backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    s.mount("https://", HTTPAdapter(max_retries=r))
    s.headers.update({"User-Agent": "DevSecOpsBrief/Pro/1.0 (+github-actions)"})
    return s

SESSION = make_session()

# ----------------------------- Helpers ----------------------------------------
def now_local():
    return datetime.now(ZoneInfo(LOCAL_TZ))

def within_0830_guard():
    if not STRICT_0830:
        return True
    n = now_local()
    if SKIP_WEEKENDS and n.weekday() >= 5:
        return False
    return (n.hour == 8) and (abs(n.minute - 30) <= STRICT_0830_TOL_MIN)

def esc(s: str) -> str:
    return (s or "").replace("\r", "").strip()

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

def keyword_hit(s: str, keywords):
    t = (s or "").lower()
    return any(k in t for k in keywords)

# ----------------------------- Data collectors --------------------------------
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
                "dueDate": v.get("dueDate"),
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
                items.append({"title": esc(getattr(e, "title", "")), "link": esc(getattr(e, "link", "")), "ts": ts})
        except Exception:
            continue

    # score recency + keyword boost
    def score(it):
        bonus = 6 * 3600 if keyword_hit(it["title"], HEADLINE_KEYWORDS) else 0
        return (it["ts"] or 0) + bonus

    # de-dup by normalized title
    items.sort(key=score, reverse=True)
    seen, uniq = set(), []
    for it in items:
        key = it["title"].lower()
        if key not in seen:
            seen.add(key)
            uniq.append(it)
        if len(uniq) >= n:
            break
    return uniq

# ----------------------------- Brief builder ----------------------------------
def build_brief():
    kev = get_kev()
    epss = get_epss()

    kev_set = {k["cve"] for k in kev}
    epss_only = [e for e in epss if e["cve"] not in kev_set][:EPSS_LIMIT]
    hl = safe_top_headlines(FEED_COUNT)

    # Header
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

    # Headlines
    lines.append("")
    lines.append("Situational awareness:")
    if hl:
        for h in hl:
            title = esc(h["title"])
            link = esc(h["link"])
            lines.append(f"- {title} — {link}")
    else:
        lines.append("- (No headlines available)")

    # Controls of the day (tight, actionable)
    lines.append("")
    lines.append("Controls today:")
    lines.append("• Fast-track KEV patching; restrict public access for impacted edge apps until patched.")
    lines.append("• Validate internet exposure for VPNs, gateways, Exchange/OWA, Confluence, Git* servers.")
    lines.append("• Deploy detections: auth anomalies, webshell writes, unexpected service restarts.")
    lines.append("• Backups: confirm recent, offline/immutable for systems tied to RCE/priv-esc CVEs.")

    msg = "\n".join(lines)
    # keep safe under Telegram cap
    return msg[:TELEGRAM_MAX]

# ----------------------------- Telegram sender --------------------------------
def send_telegram(text: str):
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_id_single = os.environ.get("TELEGRAM_CHAT_ID")
    chat_ids = []
    if TELEGRAM_CHAT_IDS:
        chat_ids = [c.strip() for c in TELEGRAM_CHAT_IDS.split(",") if c.strip()]
    elif chat_id_single:
        chat_ids = [chat_id_single]
    else:
        raise RuntimeError("No TELEGRAM_CHAT_ID or TELEGRAM_CHAT_IDS provided.")

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    chunks = split_chunks(text)

    results = []
    for cid in chat_ids:
        for i, chunk in enumerate(chunks, 1):
            payload = {"chat_id": cid, "text": chunk, "disable_web_page_preview": True}
            r = SESSION.post(url, data=payload, timeout=30)
            if r.status_code >= 400:
                # surface error in logs; raise for visibility in Actions
                print(f"[telegram] ERROR {r.status_code} {r.text}")
            r.raise_for_status()
            results.append(r.json())
            time.sleep(0.3)
    return results

# --------------------------------- Main ---------------------------------------
if __name__ == "__main__":
    if not within_0830_guard():
        print("[guard] Not within 08:30 window; exiting.")
        raise SystemExit(0)

    brief = build_brief()
    send_telegram(brief)
