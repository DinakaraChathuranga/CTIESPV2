# services/ingestion/normalizer.py
"""
Common normalized CVE format for all ingestion sources.
All pollers (NVD, CISA KEV, RSS) produce NormalizedCVE objects
which are then persisted to the database in a single function.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Any
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models.db_models import CVE
from services.ingestion.epss import fetch_epss_scores, compute_priority_score
from core.config import SEVERITY_RANK, settings

logger = logging.getLogger(__name__)


@dataclass
class NormalizedCVE:
    cve_ids: str
    title: str
    severity: str
    source: str

    vuln_type: str = ""
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    is_kev: bool = False
    affected_products: List[str] = field(default_factory=list)
    cpe_strings: List[str] = field(default_factory=list)
    description: str = ""
    impact: List[str] = field(default_factory=list)
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    remediation: str = ""
    refs: List[str] = field(default_factory=list)
    vendor_advisory: Optional[str] = None
    patch_available: bool = False
    published_at: Optional[datetime] = None
    raw_data: Optional[Any] = None

    def passes_severity_filter(self) -> bool:
        min_rank = SEVERITY_RANK.get(settings.MIN_SEVERITY.upper(), 3)
        return SEVERITY_RANK.get(self.severity.upper(), 0) >= min_rank


async def cve_exists(cve_ids: str, db: AsyncSession) -> Optional[CVE]:
    result = await db.execute(select(CVE).where(CVE.cve_ids == cve_ids))
    return result.scalar_one_or_none()


async def upsert_cves(
    normalized_list: List[NormalizedCVE],
    db: AsyncSession,
) -> tuple[int, int]:
    """
    Persist a list of NormalizedCVE objects to the database.
    - Skips existing CVEs (by cve_ids unique key).
    - Enriches with EPSS scores in batch.
    - Computes priority_score for each.

    Returns (new_count, skipped_count).
    """
    if not normalized_list:
        return 0, 0

    # Batch EPSS enrichment
    cve_id_list = [n.cve_ids for n in normalized_list if n.cve_ids]
    epss_data = {}
    try:
        epss_data = await fetch_epss_scores(cve_id_list)
    except Exception as e:
        logger.warning(f"[Normalizer] EPSS fetch failed: {e}")

    new_count = 0
    skipped_count = 0

    for norm in normalized_list:
        if not norm.cve_ids or not norm.passes_severity_filter():
            skipped_count += 1
            continue

        # Skip if already exists
        existing = await cve_exists(norm.cve_ids, db)
        if existing:
            # Update EPSS + KEV flag if this is a richer source
            changed = False
            if norm.is_kev and not existing.is_kev:
                existing.is_kev = True
                existing.severity = "CRITICAL"
                changed = True
            if epss_data.get(norm.cve_ids) and existing.epss_score is None:
                ep = epss_data[norm.cve_ids]
                existing.epss_score = ep["epss"]
                existing.epss_percentile = ep["percentile"]
                existing.priority_score = compute_priority_score(
                    existing.cvss_score, ep["epss"], existing.is_kev, existing.severity
                )
                changed = True
            if changed:
                db.add(existing)
            skipped_count += 1
            continue

        # Enrich with EPSS
        ep = epss_data.get(norm.cve_ids, {})
        epss_score = ep.get("epss") or norm.epss_score
        epss_pct   = ep.get("percentile") or norm.epss_percentile

        priority = compute_priority_score(norm.cvss_score, epss_score, norm.is_kev, norm.severity)

        # Build default impact list if not provided
        impact = norm.impact or _build_default_impact(norm)

        cve = CVE(
            cve_ids=norm.cve_ids,
            title=norm.title,
            vuln_type=norm.vuln_type or "",
            severity=norm.severity.upper(),
            cvss_score=norm.cvss_score,
            cvss_vector=norm.cvss_vector,
            epss_score=epss_score,
            epss_percentile=epss_pct,
            priority_score=priority,
            is_kev=norm.is_kev,
            affected_products=norm.affected_products or [],
            cpe_strings=norm.cpe_strings or [],
            description=norm.description or "",
            impact=impact,
            attack_vector=norm.attack_vector,
            attack_complexity=norm.attack_complexity,
            privileges_required=norm.privileges_required,
            remediation=norm.remediation or _default_remediation(),
            refs=norm.refs or [],
            vendor_advisory=norm.vendor_advisory,
            patch_available=norm.patch_available,
            source=norm.source,
            published_at=norm.published_at,
            raw_data=norm.raw_data,
        )
        try:
            db.add(cve)
            await db.commit()
            new_count += 1
        except Exception as e:
            await db.rollback()
            logger.warning(f"[Normalizer] Skipped duplicate {norm.cve_ids}: {e}")
            skipped_count += 1

    return new_count, skipped_count


def _build_default_impact(norm: NormalizedCVE) -> List[str]:
    impacts = []
    av = (norm.attack_vector or "").lower()
    sev = norm.severity.upper()

    if sev == "CRITICAL":
        impacts.append("Full system compromise possible")
    if "remote" in av or "network" in av:
        impacts.append("Remotely exploitable without authentication")
    if sev in ("CRITICAL", "HIGH"):
        impacts.append("Potential for privilege escalation to root/admin")
        impacts.append("Unauthorized access to sensitive data and configurations")
    if norm.is_kev:
        impacts.append("Actively exploited by threat actors in the wild")

    impacts.append("Disruption of security monitoring and logging capabilities")
    return impacts


def _default_remediation() -> str:
    return (
        "Apply the latest security patches provided by the vendor immediately. "
        "Review vendor security advisory for specific patch versions and workarounds. "
        "Implement network-level controls to restrict access to affected services where "
        "patching is not immediately possible. Monitor for indicators of compromise."
    )
