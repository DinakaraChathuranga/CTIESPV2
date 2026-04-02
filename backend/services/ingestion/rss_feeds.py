# services/ingestion/rss_feeds.py
"""
RSS/Atom feed parser for security news sources.
Extracts CVE IDs mentioned in articles and creates lightweight CVE stubs
that get enriched later from NVD if they don't already exist.
"""
import re
import logging
import asyncio
from datetime import datetime, timedelta
from typing import List, Optional
from email.utils import parsedate_to_datetime

import httpx
import feedparser
from bs4 import BeautifulSoup

from core.config import settings
from services.ingestion.normalizer import NormalizedCVE

logger = logging.getLogger(__name__)

# CVE ID pattern
CVE_RE = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
# Severity keywords
SEV_KEYWORDS = {
    "CRITICAL": ["critical", "remote code execution", "rce", "unauthenticated", "zero-day", "0day"],
    "HIGH": ["high severity", "privilege escalation", "authentication bypass", "sql injection"],
    "MEDIUM": ["medium", "cross-site", "xss", "csrf", "information disclosure"],
}

RSS_FEEDS = settings.RSS_FEEDS


def _detect_severity(text: str) -> str:
    text_lower = text.lower()
    for sev, keywords in SEV_KEYWORDS.items():
        if any(kw in text_lower for kw in keywords):
            return sev
    return "HIGH"  # security news items default to HIGH


def _clean_html(html: str) -> str:
    if not html:
        return ""
    soup = BeautifulSoup(html, "lxml")
    return soup.get_text(separator=" ", strip=True)[:2000]


def _parse_date(entry: dict) -> Optional[datetime]:
    for field in ("published", "updated"):
        raw = entry.get(field) or entry.get(f"{field}_parsed")
        if raw:
            try:
                if isinstance(raw, str):
                    return parsedate_to_datetime(raw).replace(tzinfo=None)
                if hasattr(raw, 'tm_year'):
                    import time
                    return datetime(*raw[:6])
            except Exception:
                pass
    return None


async def _fetch_feed(url: str) -> list:
    """Async-friendly feedparser wrapper."""
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "CTI-Platform/2.0 (security research)"})
            resp.raise_for_status()
            feed = feedparser.parse(resp.text)
            return feed.entries
    except Exception as e:
        logger.warning(f"[RSS] Failed to fetch {url}: {e}")
        return []


async def poll_rss_feeds(since: Optional[datetime] = None) -> List[NormalizedCVE]:
    """
    Poll all configured RSS feeds. Extract CVE IDs from article text.
    Returns NormalizedCVE stubs for any CVE IDs found.
    Returns only articles with CVE mentions (for security-relevant filtering).
    """
    cutoff = since or (datetime.utcnow() - timedelta(hours=12))
    found_cves: dict[str, NormalizedCVE] = {}   # keyed by CVE ID to deduplicate

    # Fetch all feeds concurrently
    feed_tasks = [_fetch_feed(url) for url in RSS_FEEDS]
    all_entries = await asyncio.gather(*feed_tasks)

    for entries in all_entries:
        for entry in entries:
            pub_date = _parse_date(entry)
            if pub_date and pub_date < cutoff:
                continue

            title = entry.get("title", "")
            summary_raw = entry.get("summary", "") or entry.get("description", "")
            content_raw = ""
            for c in entry.get("content", []):
                content_raw += c.get("value", "")

            summary = _clean_html(summary_raw or content_raw)
            full_text = f"{title}. {summary}"

            # Extract all CVE IDs mentioned
            cve_ids_found = list(set(CVE_RE.findall(full_text)))
            if not cve_ids_found:
                continue

            severity = _detect_severity(full_text)
            link = entry.get("link", "")

            for cve_id in cve_ids_found:
                cve_id_upper = cve_id.upper()
                if cve_id_upper not in found_cves:
                    found_cves[cve_id_upper] = NormalizedCVE(
                        cve_ids=cve_id_upper,
                        title=title[:200] or cve_id_upper,
                        vuln_type="",
                        severity=severity,
                        cvss_score=None,
                        affected_products=[],
                        cpe_strings=[],
                        description=summary[:1000],
                        refs=[link] if link else [],
                        source="rss",
                        published_at=pub_date,
                        raw_data={"title": title, "link": link, "summary": summary[:500]},
                    )
                else:
                    # Upgrade severity if we see it mentioned in a more severe context
                    existing = found_cves[cve_id_upper]
                    from core.config import SEVERITY_RANK
                    if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(existing.severity, 0):
                        existing.severity = severity

    results = list(found_cves.values())
    logger.info(f"[RSS] Found {len(results)} unique CVE mentions across {len(RSS_FEEDS)} feeds")
    return results
