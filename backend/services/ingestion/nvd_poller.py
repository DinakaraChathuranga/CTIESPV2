# services/ingestion/nvd_poller.py
"""
NVD CVE API 2.0 poller.
Fetches structured CVE data including CVSS scores, CPE strings, CWE types.
Rate limits: 5 req/30s without API key, 50 req/30s with key.
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

import httpx

from core.config import settings, SEVERITY_RANK
from services.ingestion.normalizer import NormalizedCVE

logger = logging.getLogger(__name__)

NVD_URL = settings.NVD_BASE_URL
API_KEY = settings.NVD_API_KEY
# Delay between requests: 0.6s with key, 6s without
REQUEST_DELAY = 0.65 if API_KEY else 6.1


def _get_cvss_data(item: dict) -> dict:
    """Extract CVSS metrics from NVD item — prefer v3.1, fall back to v3.0, v2."""
    metrics = item.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            return {
                "severity":           (data.get("baseSeverity") or "MEDIUM").upper(),
                "cvss_score":         data.get("baseScore"),
                "cvss_vector":        data.get("vectorString"),
                "attack_vector":      data.get("attackVector") or data.get("accessVector"),
                "attack_complexity":  data.get("attackComplexity") or data.get("accessComplexity"),
                "privileges_required": data.get("privilegesRequired"),
            }
    return {"severity": "MEDIUM", "cvss_score": None, "cvss_vector": None,
            "attack_vector": None, "attack_complexity": None, "privileges_required": None}


def _get_cpe_data(item: dict) -> tuple[list, list]:
    """Extract CPE 2.3 strings and human-readable product names."""
    cpe_strings: List[str] = []
    products: List[str] = []

    for cfg in item.get("configurations", []):
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                if cpe and match.get("vulnerable", True):
                    cpe_strings.append(cpe)
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        vendor  = parts[3].replace("_", " ").title()
                        product = parts[4].replace("_", " ").title()
                        display = f"{vendor} {product}".strip()
                        if display not in products:
                            products.append(display)

    return cpe_strings[:50], products[:20]  # cap to avoid absurd lists


def _get_description(item: dict) -> str:
    for d in item.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _get_weaknesses(item: dict) -> str:
    types = []
    for w in item.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("lang") == "en" and d.get("value") != "NVD-CWE-Other":
                types.append(d["value"])
    return ", ".join(types[:5])


def _get_refs(item: dict) -> List[str]:
    return [r.get("url", "") for r in item.get("references", []) if r.get("url")][:10]


def _nvd_item_to_normalized(item: dict) -> Optional[NormalizedCVE]:
    """Convert a raw NVD CVE item to a NormalizedCVE."""
    cve_id = item.get("id", "")
    if not cve_id:
        return None

    cvss = _get_cvss_data(item)

    # Filter by minimum severity
    rank = SEVERITY_RANK.get(cvss["severity"], 0)
    min_rank = SEVERITY_RANK.get(settings.MIN_SEVERITY, 3)
    if rank < min_rank:
        return None

    cpe_strings, products = _get_cpe_data(item)
    # Fallback: extract products from title/description when NVD has no CPE data yet
    if not products:
        title_text = item.get("descriptions", [{}])[0].get("value", "") if isinstance(item, dict) else ""
        import re
        vendors = ["Microsoft","Cisco","Fortinet","VMware","Apache","Oracle","IBM",
                   "Juniper","F5","Citrix","Atlassian","GitLab","Jenkins","WordPress",
                   "Linux","Windows","Firefox","Chrome","Exchange","SharePoint",
                   "Kubernetes","Docker","Splunk","MongoDB","PostgreSQL","MySQL",
                   "Redis","Palo Alto","SolarWinds","Ivanti","Progress","OpenSSL",
                   "nginx","Drupal","PHP","Safari","Edge","Azure","Android"]
        combined = title_text
        for v in vendors:
            if v.lower() in combined.lower():
                products.append(v)
    desc = _get_description(item)
    vuln_type = _get_weaknesses(item)
    refs = _get_refs(item)

    published = item.get("published", "")
    published_at = None
    if published:
        try:
            published_at = datetime.fromisoformat(published.replace("Z", "+00:00"))
        except Exception:
            pass

    return NormalizedCVE(
        cve_ids=cve_id,
        title=desc[:200] or cve_id,
        vuln_type=vuln_type,
        severity=cvss["severity"],
        cvss_score=cvss["cvss_score"],
        cvss_vector=cvss["cvss_vector"],
        affected_products=products,
        cpe_strings=cpe_strings,
        description=desc,
        attack_vector=cvss["attack_vector"],
        attack_complexity=cvss["attack_complexity"],
        privileges_required=cvss["privileges_required"],
        refs=refs,
        source="nvd",
        published_at=published_at,
        raw_data=item,
    )


async def _fetch_nvd_page(client: httpx.AsyncClient, params: dict) -> dict:
    """Fetch one page from NVD with adaptive 429 backoff and server-error retry."""
    headers = {"apiKey": API_KEY} if API_KEY else {}
    for attempt in range(5):
        try:
            resp = await client.get(NVD_URL, params=params, headers=headers, timeout=30.0)
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            wait = min(10 * (2 ** attempt), 60)
            logger.warning(f"[NVD] Network error (attempt {attempt+1}/5): {e} — retrying in {wait}s")
            await asyncio.sleep(wait)
            continue

        if resp.status_code == 429:
            # Respect Retry-After header; fall back to adaptive backoff
            retry_after = int(resp.headers.get("Retry-After", 0))
            wait = retry_after if retry_after > 0 else (30 * (2 ** attempt) if not API_KEY else 10 * (2 ** attempt))
            wait = min(wait, 120)
            logger.warning(f"[NVD] Rate limited (429) — waiting {wait}s (attempt {attempt+1}/5)")
            await asyncio.sleep(wait)
            continue

        if resp.status_code >= 500:
            wait = min(10 * (2 ** attempt), 60)
            logger.warning(f"[NVD] Server error {resp.status_code} — retrying in {wait}s")
            await asyncio.sleep(wait)
            continue

        resp.raise_for_status()
        return resp.json()

    raise RuntimeError("NVD API unavailable after 5 retries")


async def poll_nvd(since: Optional[datetime] = None) -> List[NormalizedCVE]:
    """
    Fetch recent CVEs from NVD API 2.0.
    Returns list of NormalizedCVE objects that pass the severity filter.
    """
    now = datetime.utcnow()
    if since is None:
        since = now - timedelta(days=settings.INITIAL_LOOKBACK_DAYS)

    pub_start = since.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end   = now.strftime("%Y-%m-%dT%H:%M:%S.000")

    logger.info(f"[NVD] Fetching CVEs {pub_start} → {pub_end}")

    all_cves: List[NormalizedCVE] = []
    start_index = 0
    total = None

    async with httpx.AsyncClient() as client:
        while True:
            params = {
                "pubStartDate": pub_start,
                "pubEndDate":   pub_end,
                "startIndex":   start_index,
                "resultsPerPage": 100,
            }
            try:
                data = await _fetch_nvd_page(client, params)
            except Exception as e:
                logger.error(f"[NVD] Fetch error at index {start_index}: {e}")
                break

            vulns = data.get("vulnerabilities", [])
            if total is None:
                total = data.get("totalResults", 0)
                logger.info(f"[NVD] Total results: {total}")

            for vuln_wrapper in vulns:
                item = vuln_wrapper.get("cve", {})
                normalized = _nvd_item_to_normalized(item)
                if normalized:
                    all_cves.append(normalized)

            start_index += len(vulns)
            logger.info(f"[NVD] Processed {start_index}/{total}")

            if start_index >= (total or 0) or not vulns:
                break

            await asyncio.sleep(REQUEST_DELAY)

    logger.info(f"[NVD] Done — {len(all_cves)} CVEs after severity filter")
    return all_cves
