import os, requests, time
from datetime import datetime, timedelta, timezone

try:
    import feedparser  # pip install feedparser
except Exception:
    feedparser = None

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss?epss-gt=0.5&order=!epss&limit=1000"

HEADLINE_FEEDS = [
    "https://www.bleepingcomputer.com/feed/",
    "https://www.darkreading.com/rss.xml",
    "https://therecord.media/feed",
    "https://www.microsoft.com/en-us/security/blog/feed/",
    "https://blog.google/threat-analysis-group/rss/",
    "https://aws.amazon.com/blogs/security/feed/",
]

def get_kev_last_24h():
    y = (datetime.now(timezone.utc) - timedelta(days=1)).date().isoformat()
    r = requests.get(KEV_URL, timeout=30)
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities", [])
    out = []
    for v in vulns:
        if v.get("dateAdded", "") >= y:
            out.append({
                "cve": v.get("cveID"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "desc": (v.get("shortDescription") or "").strip()
            })
    return out

def get_epss_high():
    r = requests.get(EPSS_URL, timeout=30)
    r.raise_for_status()
    data = r.json().get("data", [])
    out = []
    for d in data:
        try:
            epss = float(d.get("epss", "0"))
            pct = float(d.get("percentile", "0"))
        except:
            continue
        out.append({"cve": d["cve"], "epss": epss, "pct": pct})
    out.sort(key=lambda x: x["epss"], reverse=True)
    return out

def safe_top_headlines(n=3):
    if not feedparser:
        return []
    items = []
    for url in HEADLINE_FEEDS:
        try:
            f = feedparser.parse(url)
            for e in f.entries[:5]:
                ts = None
                if getattr(e, "published_parsed", None):
                    ts = time.mktime(e.published_parsed)
                elif getattr(e, "updated_parsed", None):
                    ts = time.mktime(e.updated_parsed)
                items.append({"title": e.title.strip(), "link": e.link, "ts": ts or 0})
        except Exception:
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

def build_brief():
    kev = get_kev_last_24h()
    epss = get_epss_high()
    kev_set = {k["cve"] for k in kev}
    epss_only = [e for e in epss if e["cve"] not in kev_set][:5]
    hl = safe_top_headlines(3)

    lines = []
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

    msg = "Daily DevSecOps brief\n" + "\n".join(lines)
    return msg[:3900]

def send_telegram(text: str):
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_id = os.environ["TELEGRAM_CHAT_ID"]
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    r = requests.post(url, data={"chat_id": chat_id, "text": text, "disable_web_page_preview": True}, timeout=30)
    r.raise_for_status()
    return r.json()

if __name__ == "__main__":
    brief = build_brief()
    send_telegram(brief)
