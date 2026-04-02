# services/ingestion/cisa_kev.py
"""CISA Known Exploited Vulnerabilities catalog poller."""
import logging
from datetime import datetime, timedelta
from typing import List, Optional
import httpx
from core.config import settings
from services.ingestion.normalizer import NormalizedCVE

logger = logging.getLogger(__name__)


async def poll_cisa_kev(since: Optional[datetime] = None) -> List[NormalizedCVE]:
    """Fetch CISA KEV entries added since `since`."""
    logger.info("[CISA KEV] Fetching catalog...")
    results: List[NormalizedCVE] = []
    cutoff = since or (datetime.utcnow() - timedelta(days=settings.INITIAL_LOOKBACK_DAYS))

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(settings.CISA_KEV_URL)
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        logger.error(f"[CISA KEV] Error: {e}")
        return []

    for entry in data.get("vulnerabilities", []):
        added = entry.get("dateAdded", "")
        try:
            added_dt = datetime.strptime(added, "%Y-%m-%d")
        except Exception:
            continue
        if added_dt < cutoff:
            continue

        vendor_product = f"{entry.get('vendorProject','')} {entry.get('product','')}".strip()
        short_desc = entry.get("shortDescription", "")

        results.append(NormalizedCVE(
            cve_ids=entry.get("cveID", ""),
            title=entry.get("vulnerabilityName") or entry.get("cveID", ""),
            vuln_type=short_desc[:200],
            severity="CRITICAL",   # KEV = actively exploited → treat as at least HIGH
            cvss_score=None,
            affected_products=[vendor_product] if vendor_product else [],
            cpe_strings=[],
            description=short_desc,
            attack_vector="Network",
            remediation=entry.get("requiredAction", "Apply vendor patch per CISA guidance."),
            refs=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
            source="cisa_kev",
            is_kev=True,
            published_at=added_dt,
            raw_data=entry,
        ))

    logger.info(f"[CISA KEV] {len(results)} new entries since {cutoff.date()}")
    return results
