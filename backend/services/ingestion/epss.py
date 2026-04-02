# services/ingestion/epss.py
"""
EPSS (Exploit Prediction Scoring System) enrichment.
Fetches exploit probability scores from first.org API.
"""
import logging
from typing import List, Dict, Optional
import httpx
from core.config import settings

logger = logging.getLogger(__name__)


async def fetch_epss_scores(cve_ids: List[str]) -> Dict[str, dict]:
    """
    Fetch EPSS scores for a list of CVE IDs.
    Returns dict: {cve_id: {"epss": float, "percentile": float}}
    """
    if not cve_ids:
        return {}

    results: Dict[str, dict] = {}
    # EPSS API supports up to 30 CVEs per request
    chunk_size = 30
    chunks = [cve_ids[i:i+chunk_size] for i in range(0, len(cve_ids), chunk_size)]

    async with httpx.AsyncClient(timeout=30.0) as client:
        for chunk in chunks:
            params = {"cve": ",".join(chunk)}
            try:
                resp = await client.get(settings.EPSS_API_URL, params=params)
                resp.raise_for_status()
                data = resp.json()
                for entry in data.get("data", []):
                    cve_id = entry.get("cve")
                    if cve_id:
                        results[cve_id] = {
                            "epss":       float(entry.get("epss", 0)),
                            "percentile": float(entry.get("percentile", 0)),
                        }
            except Exception as e:
                logger.warning(f"[EPSS] Error fetching chunk: {e}")

    logger.info(f"[EPSS] Fetched scores for {len(results)}/{len(cve_ids)} CVEs")
    return results


def compute_priority_score(
    cvss_score: Optional[float],
    epss_score: Optional[float],
    is_kev: bool,
    severity: str,
) -> float:
    """
    Composite priority score (0–100) for analyst triage.

    Formula:
      - CVSS component (0–40):   CVSS_score * 4
      - EPSS component (0–40):   epss_score * 40
      - KEV bonus (+20):         is actively exploited
      - Severity modifier:       CRITICAL +0, HIGH -5, MEDIUM -15, LOW -25

    Higher = more urgent.
    """
    score = 0.0

    if cvss_score is not None:
        score += min(cvss_score, 10.0) * 4.0   # max 40

    if epss_score is not None:
        score += epss_score * 40.0              # max 40

    if is_kev:
        score += 20.0

    sev_mod = {"CRITICAL": 0, "HIGH": -5, "MEDIUM": -15, "LOW": -25}
    score += sev_mod.get(severity.upper(), -15)

    return round(max(0.0, min(100.0, score)), 2)
