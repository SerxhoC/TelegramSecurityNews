#!/usr/bin/env python3
import os, time, json, logging
from datetime import datetime, timedelta, timezone
from typing import List, Dict

import requests
try:
    import feedparser  # pip install feedparser
except Exception:
    feedparser = None

from urllib3.util import Retry
from requests.adapters import HTTPAdapter

# ---- Config ----
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?epss-gt=0.5&order=!epss&limit=1000"
HEADLINE_FEEDS = [
    "https://www.bleepingcomputer.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://therecord.media/feed/",
    "https://www.microsoft.com/en-us/security/blog/feed/",
    "https://blog.google/threat-analysis-group/rss/",
    "https://aws.amazon.com/blogs/security/feed/",
]
HEADLINES_TO_INCLUDE = 3
MAX_MSG_LEN = 3900  # keep <4096 for Telegram

UA = {"User-Agent": "devsecops-brief/1.0 (+https://example.org)"}

# ---- Logging ----
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def session_with_retries(total=4, backoff=0.5) -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=total,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"]),
        raise_on_status=False,
    )
    s.mount("https://", HTTPAdapter(max_retries=retries))
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.headers.update(UA)
    return s

S = session_with_retries()

def get_kev_last_24h() -> List[Dict]:
    cutoff_date = (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()
    r = S.get(KEV_URL, timeout=30)
    r.raise_for_status()
    data = r.json()
    vulns = data.get("vulnerabilities", [])
    out = []
    for v in vulns:
        # dateAdded is YYYY-MM-DD — string compare with same format is OK
        if (v.get("dateAdded") or "") >= cutoff_date:
            out.append({
                "cve": v.get("cveID"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "desc": (v.get("shortDescription") or "").strip(),
            })
    return out

def get_epss_high() -> List[Dict]:
    r = S.get(EPSS_URL, timeout=30)
    r.raise_for_status()
    data = r.json().get("data", [])
    out = []
    for d in data:
        try:
            epss = float(d.get("epss", "0"))
            pct = float(d.get("percentile", "0"))
            out.append({"cve": d["cve"], "epss": epss, "pct": pct})
        except Exception:
            continue
    out.sort(key=lambda x: x["epss"], reverse=True)
    return out

def safe_top_headlines(n=3) -> List[Dict]:
    if not feedparser:
        logging.warning("feedparser not installed; skipping headlines.")
        return []
    items = []
    for url in HEADLINE_FEEDS:
        try:
            f = feedparser.parse(url, request_headers=UA)
            for e in f.entries[:6]:
                ts = None
                if getattr(e, "published_parsed", None):
                    ts = time.mktime(e.published_parsed)
                elif getattr(e, "updated_parsed", None):
                    ts = time.mktime(e.updated_parsed)
                title = (getattr(e, "title", "") or "").strip()
                link = getattr(e, "link", "") or ""
                if title and link:
                    items.append({"title": title, "link": link, "ts": ts or 0})
        except Exception as ex:
            logging.warning("RSS error for %s: %s", url, ex)
            continue
    items.sort(key=lambda x: x["ts"], reverse=True)
    seen, uniq = set(), []
    for it in items:
        if it["title"] not in seen:
            seen.add(it["title"])
            uniq.append(it)
        if len(uniq) >= n:
            break
    return uniq

def build_brief() -> str:
    try:
        kev = get_kev_last_24h()
    except Exception as ex:
        logging.exception("KEV fetch failed: %s", ex)
        kev = []

    try:
        epss = get_epss_high()
    except Exception as ex:
        logging.exception("EPSS fetch failed: %s", ex)
        epss = []

    kev_set = {k["cve"] for k in kev}
    epss_only = [e for e in epss if e["cve"] not in kev_set][:5]

    try:
        hl = safe_top_headlines(HEADLINES_TO_INCLUDE)
    except Exception as ex:
        logging.exception("Headlines failed: %s", ex)
        hl = []

    lines = []
    lines.append("Daily DevSecOps brief")
    lines.append("")
    lines.append("Exploited now:")
    if kev:
        for k in kev[:5]:
            lines.append(f"- {k['cve']} — {k['vendor']}/{k['product']}: {k['desc']} | Action: Patch/mitigate, add detection.")
    else:
        lines.append("- (No new KEV entries in last 24h)")

    lines.append("")
    lines.append("High-likelihood CVEs:")
    if epss_only:
        for e in epss_only:
            pct = int(round(e["pct"] * 100))
            lines.append(f"- {e['cve']} — EPSS {e['epss']:.2f} (Pctl {pct}) | Action: Prioritize remediation/detection.")
    else:
        lines.append("- (No EPSS ≥0.5 outside KEV worth noting)")

    lines.append("")
    lines.append("Situational awareness:")
    if hl:
        for h in hl:
            lines.append(f"- {h['title']} — {h['link']}")
    else:
        lines.append("- (No headlines available)")

    msg = "\n".join(lines)
    if len(msg) > MAX_MSG_LEN:
        msg = msg[:MAX_MSG_LEN]
    return msg

def send_telegram(text: str) -> Dict:
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_id = os.environ["TELEGRAM_CHAT_ID"]
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": True,
        # No parse_mode to avoid accidental Markdown formatting issues
    }
    r = S.post(url, data=payload, timeout=30)
    try:
        r.raise_for_status()
        return r.json()
    except Exception:
        logging.error("Telegram error %s: %s", r.status_code, r.text[:300])
        raise

if __name__ == "__main__":
    brief = build_brief()
    print(brief)  # visible in CI logs
    send_telegram(brief)
