# services/matching/alert_factory.py
"""
Centralised alert creation — used by all Celery tasks and API routes.
Handles the unique-constraint on (cve_id, client_id) gracefully.
"""
import logging
from typing import List, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from models.db_models import Alert, CVE
from services.matching.engine import match_cve_to_clients
from services.matching.semantic_matcher import MatchResult

logger = logging.getLogger(__name__)


async def create_alerts_for_cve(
    cve: CVE,
    db: AsyncSession,
) -> Tuple[int, List[dict]]:
    """
    Run the matching engine for a single CVE and create Alert rows.

    Returns:
        (alerts_created_count, list of match dicts)

    Silently skips alerts that already exist (unique constraint on cve_id+client_id).
    """
    matches: List[MatchResult] = await match_cve_to_clients(cve, db)
    created = 0
    match_summaries = []

    for match in matches:
        # Check if alert already exists before inserting
        existing = await db.execute(
            select(Alert).where(
                Alert.cve_id == cve.id,
                Alert.client_id == match.client_id,
            )
        )
        if existing.scalar_one_or_none():
            continue

        alert = Alert(
            cve_id=cve.id,
            client_id=match.client_id,
            match_method=match.method,
            match_score=match.score,
            matched_assets=match.matched_assets,
            matched_cpes=match.matched_cpes,
        )
        db.add(alert)
        try:
            await db.flush()   # catch constraint error per-row
            created += 1
            match_summaries.append(match.to_dict())
            logger.info(
                f"[Alert] Created for CVE={cve.cve_ids} → client={match.client_name} "
                f"method={match.method} score={match.score:.3f}"
            )
        except IntegrityError:
            await db.rollback()
            logger.debug(f"[Alert] Duplicate skipped: CVE={cve.cve_ids} client={match.client_id}")

    if created:
        await db.commit()

    return created, match_summaries


async def create_alerts_for_cve_list(
    cves: List[CVE],
    db: AsyncSession,
) -> Tuple[int, int]:
    """
    Batch alert creation for a list of CVEs.
    Returns (total_alerts_created, cves_with_matches).
    """
    total_alerts = 0
    cves_matched = 0

    for cve in cves:
        count, _ = await create_alerts_for_cve(cve, db)
        if count:
            total_alerts += count
            cves_matched += 1

    return total_alerts, cves_matched
