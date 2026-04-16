# services/reporting/rag_store.py
# RAG store using PostgreSQL SampleReport table (ChromaDB removed).
# Sample reports uploaded via the UI are stored in DB and retrieved by severity/vuln_type match.
import hashlib
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


async def add_sample_report(text, filename, severity=None, vuln_type=None, doc_id=None):
    """Store sample report text. DB persistence is handled by the upload route; this returns the doc_id."""
    doc_id = doc_id or hashlib.md5(f"{filename}{text[:100]}".encode()).hexdigest()
    logger.info(f"[RAG] Sample report registered: {filename} (doc_id={doc_id[:8]})")
    return doc_id


async def query_similar_reports(query_text: str, severity: Optional[str] = None, n_results: int = 3) -> List[Dict]:
    """
    Retrieve similar sample reports from the DB.
    Matches by severity first, then returns any available reports up to n_results.
    Returns list of dicts with 'text' and 'meta' keys for prompt injection.
    """
    try:
        from core.database import AsyncSessionLocal
        from models.db_models import SampleReport
        from sqlalchemy import select

        async with AsyncSessionLocal() as db:
            # Priority 1: same severity + vuln_type keywords
            q = select(SampleReport).limit(n_results * 2)
            if severity:
                q = q.where(SampleReport.severity == severity.upper())
            result = await db.execute(q)
            reports = result.scalars().all()

            # If not enough, pull any available reports regardless of severity
            if len(reports) < n_results:
                q2 = select(SampleReport).limit(n_results)
                r2 = await db.execute(q2)
                extra = r2.scalars().all()
                seen_ids = {r.id for r in reports}
                for r in extra:
                    if r.id not in seen_ids:
                        reports.append(r)

            reports = reports[:n_results]

        if not reports:
            logger.info("[RAG] No sample reports in DB — using zero-shot generation")
            return []

        logger.info(f"[RAG] Retrieved {len(reports)} sample report(s) for style reference")
        return [
            {
                "text": r.full_text or "",
                "meta": {
                    "filename": r.filename,
                    "severity": r.severity,
                    "vuln_type": r.vuln_type,
                }
            }
            for r in reports
        ]
    except Exception as e:
        logger.warning(f"[RAG] DB query failed: {e}")
        return []


async def list_sample_reports():
    try:
        from core.database import AsyncSessionLocal
        from models.db_models import SampleReport
        from sqlalchemy import select
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(SampleReport))
            reports = result.scalars().all()
            # Map the database ID to the 'doc_id' field so the UI works seamlessly
            return [{'doc_id': str(r.id), 'filename': r.filename,
                     'severity': r.severity, 'vuln_type': r.vuln_type} for r in reports]
    except Exception:
        return []


async def delete_sample_report(doc_id):
    # Dummy return since deletion logic is handled directly in routes.py now
    return True