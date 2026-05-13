# workers/tasks.py
"""
Celery background tasks.
All tasks follow the same pattern:
  1. Create a fresh asyncio event loop (Celery workers are sync)
  2. Open an AsyncSession inside the task
  3. Run the actual async logic
  4. Write a PollLog row on completion
"""
import asyncio
import logging
import time
import os
from datetime import datetime

from workers.celery_app import app
from core.config import settings

logger = logging.getLogger(__name__)


# ─── Event-loop helper ────────────────────────────────────────────────────────

def _run(coro):
    """Run an async coroutine from a synchronous Celery task."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("closed")
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


async def _write_poll_log(source, new_cves, new_alerts, duration, error=None):
    from core.database import AsyncSessionLocal
    from models.db_models import PollLog
    async with AsyncSessionLocal() as db:
        db.add(PollLog(
            source=source, new_cves=new_cves, new_alerts=new_alerts,
            duration_seconds=round(duration, 2), error=error,
        ))
        await db.commit()


# ─── Generic feed-poll runner ─────────────────────────────────────────────────

async def _run_feed_poll(source: str, poll_fn):
    from core.database import AsyncSessionLocal
    from models.db_models import PollLog, CVE
    from sqlalchemy import select
    from services.ingestion.normalizer import upsert_cves
    from services.matching.alert_factory import create_alerts_for_cve_list

    start = time.time()
    new_cves_total = 0
    new_alerts_total = 0
    error_msg = None

    async with AsyncSessionLocal() as db:
        try:
            # Get last successful poll time for this source
            result = await db.execute(
                select(PollLog)
                .where(PollLog.source == source, PollLog.error.is_(None))
                .order_by(PollLog.run_at.desc())
                .limit(1)
            )
            last_log = result.scalar_one_or_none()
            since = last_log.run_at if last_log else None

            # Fetch from external source
            normalized_list = await poll_fn(since=since)

            # Persist + EPSS-enrich new CVEs
            new_cves_total, skipped = await upsert_cves(normalized_list, db)
            logger.info(f"[{source}] {new_cves_total} new CVEs, {skipped} skipped/updated")

            # Run asset matching on the newly-ingested CVEs only
            if new_cves_total > 0:
                result = await db.execute(
                    select(CVE)
                    .where(CVE.source == source)
                    .order_by(CVE.date_added.desc())
                    .limit(new_cves_total)
                )
                recent_cves = result.scalars().all()
                new_alerts_total, _ = await create_alerts_for_cve_list(recent_cves, db)
                logger.info(f"[{source}] {new_alerts_total} alerts created")

        except Exception as e:
            error_msg = str(e)
            logger.error(f"[{source} task] Error: {e}", exc_info=True)

    duration = time.time() - start
    await _write_poll_log(source, new_cves_total, new_alerts_total, duration, error_msg)
    return {"source": source, "new_cves": new_cves_total, "new_alerts": new_alerts_total}


# ─── Feed tasks ───────────────────────────────────────────────────────────────

@app.task(name="workers.tasks.poll_nvd_task", bind=True, max_retries=2,
          autoretry_for=(Exception,), retry_backoff=True, retry_backoff_max=60)
def poll_nvd_task(self):
    from services.ingestion.nvd_poller import poll_nvd
    return _run(_run_feed_poll("nvd", poll_nvd))


@app.task(name="workers.tasks.poll_cisa_task", bind=True, max_retries=2,
          autoretry_for=(Exception,), retry_backoff=True, retry_backoff_max=60)
def poll_cisa_task(self):
    from services.ingestion.cisa_kev import poll_cisa_kev
    return _run(_run_feed_poll("cisa_kev", poll_cisa_kev))


@app.task(name="workers.tasks.poll_rss_task", bind=True, max_retries=2,
          autoretry_for=(Exception,), retry_backoff=True, retry_backoff_max=60)
def poll_rss_task(self):
    from services.ingestion.rss_feeds import poll_rss_feeds
    return _run(_run_feed_poll("rss", poll_rss_feeds))


@app.task(name="workers.tasks.poll_epss_task", bind=True, max_retries=2)
def poll_epss_task(self):
    """Refresh EPSS scores for CVEs that are missing them."""
    async def _refresh():
        from core.database import AsyncSessionLocal
        from models.db_models import CVE
        from services.ingestion.epss import fetch_epss_scores, compute_priority_score
        from sqlalchemy import select

        start = time.time()
        updated = 0
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(CVE).where(CVE.epss_score.is_(None)).limit(500)
            )
            cves = result.scalars().all()
            if cves:
                epss_data = await fetch_epss_scores([c.cve_ids for c in cves])
                for cve in cves:
                    ep = epss_data.get(cve.cve_ids)
                    if ep:
                        cve.epss_score      = ep["epss"]
                        cve.epss_percentile = ep["percentile"]
                        cve.priority_score  = compute_priority_score(
                            cve.cvss_score, ep["epss"], cve.is_kev, cve.severity
                        )
                        db.add(cve)
                        updated += 1
                if updated:
                    await db.commit()
        await _write_poll_log("epss", 0, 0, time.time() - start)
        logger.info(f"[EPSS task] Updated {updated} CVEs")
        return {"updated": updated}

    return _run(_refresh())


# ─── Report generation ────────────────────────────────────────────────────────

@app.task(name="workers.tasks.generate_report_task", bind=True, max_retries=1,
          time_limit=300, soft_time_limit=270)
def generate_report_task(self, alert_id: str):
    """Generate AI report + DOCX document for an approved alert."""
    async def _generate():
        from core.database import AsyncSessionLocal
        from models.db_models import Alert, Report
        from services.reporting.report_writer import generate_report_data
        from services.reporting.docx_generator import generate_docx
        from sqlalchemy import select

        async with AsyncSessionLocal() as db:
            result = await db.execute(select(Alert).where(Alert.id == alert_id))
            alert = result.scalar_one_or_none()
            if not alert:
                raise ValueError(f"Alert {alert_id} not found")

            cve, client = alert.cve, alert.client
            if not cve or not client:
                raise ValueError(f"Alert {alert_id} missing CVE or client")

            logger.info(f"[Report] Generating: {cve.cve_ids} → {client.name}")

            # Step 1 — AI generation with Postgres RAG
            report_data, rag_filenames = await generate_report_data(cve, client, alert)

            # Step 2 — DOCX rendering
            alert_number = report_data.get("alert_number", "ADVISORY")
            
            # Ensure the output directory exists
            os.makedirs(settings.REPORT_OUTPUT_DIR, exist_ok=True)
            
            # Generate the docx filename and output path
            pdf_filename = f"{alert_number}_advisory.docx"
            pdf_path = os.path.join(settings.REPORT_OUTPUT_DIR, pdf_filename)
            
            # Call the updated DOCX generator
            generate_docx(report_data, client.name, alert_number, pdf_path)

            # Step 3 — Upsert report row (handles regeneration)
            existing = (await db.execute(
                select(Report).where(Report.alert_id == alert.id)
            )).scalar_one_or_none()

            # Note: We keep the DB columns named pdf_path and pdf_filename to avoid schema migrations,
            # but they now store the .docx file references.
            if existing:
                existing.alert_number      = alert_number
                existing.report_data       = report_data
                existing.pdf_path          = pdf_path
                existing.pdf_filename      = pdf_filename
                existing.rag_examples_used = rag_filenames
                existing.status            = "draft"
                existing.generated_at      = datetime.utcnow()
                db.add(existing)
                report_id = existing.id
            else:
                new_report = Report(
                    alert_id=alert.id, cve_id=cve.id, client_id=client.id,
                    alert_number=alert_number, report_data=report_data,
                    pdf_path=pdf_path, pdf_filename=pdf_filename,
                    rag_examples_used=rag_filenames,
                )
                db.add(new_report)
                await db.flush()
                report_id = new_report.id

            await db.commit()
            logger.info(
                f"[Report] Done: {alert_number} | DOCX: {pdf_filename} "
                f"| RAG examples: {len(rag_filenames)}"
            )
            return {"report_id": report_id, "alert_number": alert_number,
                    "docx": pdf_filename, "rag_used": rag_filenames}

    return _run(_generate())



# ─── Full CVE re-matching ─────────────────────────────────────────────────────

@app.task(name="workers.tasks.rematch_all_cves_task", time_limit=3600, soft_time_limit=3500)
def rematch_all_cves_task():
    """Re-run matching for all existing HIGH/CRITICAL CVEs with current threshold."""
    async def _rematch():
        from core.database import AsyncSessionLocal
        from services.matching.engine import rematch_all_cves
        async with AsyncSessionLocal() as db:
            result = await rematch_all_cves(db)
        return result
    return _run(_rematch())

# ─── Asset embedding ──────────────────────────────────────────────────────────

@app.task(name="workers.tasks.embed_assets_task")
def embed_assets_task():
    """Batch-embed client assets that don't have vector embeddings yet."""
    async def _embed():
        from core.database import AsyncSessionLocal
        from services.matching.engine import embed_all_assets
        async with AsyncSessionLocal() as db:
            count = await embed_all_assets(db)
        return {"embedded": count}
    return _run(_embed())