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

    auto_alert_ids = []
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

                # Collect high-confidence alerts for auto-pipeline
                if new_alerts_total > 0:
                    from datetime import timedelta
                    from models.db_models import Alert
                    cutoff = datetime.utcnow() - timedelta(seconds=60)
                    hc = await db.execute(
                        select(Alert)
                        .where(
                            Alert.match_score >= 0.95,
                            Alert.status == "pending",
                            Alert.created_at >= cutoff,
                        )
                        .limit(100)
                    )
                    auto_alert_ids = [str(a.id) for a in hc.scalars().all()]
                    if auto_alert_ids:
                        logger.info(f"[{source}] {len(auto_alert_ids)} alerts queued for auto-pipeline")

        except Exception as e:
            error_msg = str(e)
            logger.error(f"[{source} task] Error: {e}", exc_info=True)

    # Trigger auto-pipeline outside db session
    for aid in auto_alert_ids:
        auto_process_alert_task.delay(aid)

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

            # ── Auto-send the email immediately — no orphan drafts ──
            try:
                from api.routes import _send_report_email
                from sqlalchemy.orm import selectinload
                send_q = await db.execute(
                    select(Report)
                    .options(selectinload(Report.client))
                    .where(Report.id == report_id)
                )
                report_to_send = send_q.scalar_one()
                if report_to_send.client and (report_to_send.client.email or "").strip():
                    _send_report_email(report_to_send)
                    report_to_send.status = "sent"
                    await db.commit()
                    logger.info(f"[Report] Auto-sent: {alert_number} -> {report_to_send.client.email}")
                else:
                    logger.warning(f"[Report] Cannot auto-send {alert_number}: no client email")
            except Exception as send_err:
                logger.error(f"[Report] Auto-send failed for {alert_number}: {send_err}")

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

# ─── Auto-pipeline ────────────────────────────────────────────────────────────

@app.task(name="workers.tasks.auto_process_alert_task", bind=True, max_retries=1,
          time_limit=600, soft_time_limit=570)
def auto_process_alert_task(self, alert_id: str):
    """Auto-pipeline: AI verify → generate report → send email (score >= 0.95 only)."""
    async def _auto():
        import os
        from core.database import AsyncSessionLocal
        from models.db_models import Alert, Report
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload
        from services.matching.verifier import verify_cve_asset_match
        from services.reporting.report_writer import generate_report_data
        from services.reporting.docx_generator import generate_docx
        from api.routes import _send_report_email

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Alert)
                .options(selectinload(Alert.cve), selectinload(Alert.client))
                .where(Alert.id == alert_id)
            )
            alert = result.scalar_one_or_none()
            if not alert or alert.status != "pending":
                logger.info(f"[AutoPipeline] Skipping {alert_id}: not found or not pending")
                return

            cve, client = alert.cve, alert.client
            if not cve or not client:
                logger.error(f"[AutoPipeline] Alert {alert_id} missing CVE or client")
                return

            asset_name = (alert.matched_assets or ["Unknown asset"])[0]
            score = float(alert.match_score or 0)

            # Early exit: skip if no email — saves OpenAI calls
            if not (client.email or "").strip():
                logger.warning(f"[AutoPipeline] Skipping {alert_id}: client '{client.name}' has no email — saving OpenAI calls")
                return

            # Early exit: Windows-related CVEs require manual analyst verification
            def _is_windows_cve(cve_obj):
                """Detect Windows-related CVEs from products, CPEs, title, and description."""
                haystack = " ".join([
                    " ".join(cve_obj.affected_products or []),
                    " ".join(cve_obj.cpe_strings or []),
                    cve_obj.title or "",
                    cve_obj.description or "",
                ]).lower()
                # Windows-specific keywords (avoid generic "microsoft" which matches Office, Edge, etc.)
                windows_indicators = [
                    "windows", "win32", "win64", "win10", "win11",
                    "microsoft windows", "windows server",
                    "cpe:2.3:o:microsoft:windows",
                ]
                return any(kw in haystack for kw in windows_indicators)

            # Also detect Microsoft Office and Edge
            def _ms_product_match(cve_obj):
                haystack = " ".join([
                    " ".join(cve_obj.affected_products or []),
                    " ".join(cve_obj.cpe_strings or []),
                    cve_obj.title or "",
                    cve_obj.description or "",
                ]).lower()
                if "microsoft office" in haystack or "ms office" in haystack or "cpe:2.3:a:microsoft:office" in haystack:
                    return "Office"
                if "microsoft edge" in haystack or "cpe:2.3:a:microsoft:edge" in haystack:
                    return "Edge"
                return None

            ms_product = _ms_product_match(cve)
            hold_reason = None
            if _is_windows_cve(cve):
                hold_reason = "Windows-related"
            elif ms_product:
                hold_reason = f"Microsoft {ms_product}"

            if hold_reason:
                logger.info(
                    f"[AutoPipeline] Holding {alert_id} for manual review: "
                    f"{hold_reason} CVE {cve.cve_ids} requires analyst verification"
                )
                marker = f"[Auto-pipeline] Held for manual review: {hold_reason} CVE."
                if not alert.notes or marker not in alert.notes:
                    alert.notes = (alert.notes + "\n" if alert.notes else "") + marker
                    await db.commit()
                return

            logger.info(f"[AutoPipeline] Starting: {cve.cve_ids} → {client.name} (score={score:.2f})")

            # ── Step 1: AI verification ───────────────────────────────────────
            verif = await verify_cve_asset_match(
                cve_id=cve.cve_ids, title=cve.title or "",
                description=cve.description or "",
                affected_products=cve.affected_products or [],
                cpe_strings=cve.cpe_strings or [],
                vuln_type=cve.vuln_type or "",
                asset_name=asset_name, client_name=client.name,
                match_method=alert.match_method or "", match_score=score,
            )

            verdict = (verif.get("verdict") or "").upper()
            logger.info(f"[AutoPipeline] AI verdict: {verdict} for {alert_id}")

            for field, value in {
                "ai_verdict": verdict,
                "ai_confidence": verif.get("confidence"),
                "ai_reason": verif.get("reason"),
                "ai_recommended_action": verif.get("recommended_action"),
                "ai_verified_at": datetime.utcnow(),
                "ai_verified_by": "auto-pipeline",
                "ai_model": settings.OPENAI_MODEL,
            }.items():
                if hasattr(alert, field):
                    setattr(alert, field, value)

            if "APPROVE" not in verdict and "MATCH" not in verdict:
                await db.commit()
                logger.info(f"[AutoPipeline] Alert {alert_id} not approved, stopping")
                return

            if hasattr(alert, "status"):
                alert.status = "approved"
            await db.commit()

            # ── Step 2: Generate report ───────────────────────────────────────
            logger.info(f"[AutoPipeline] Generating report for {alert_id}")
            report_data, rag_filenames = await generate_report_data(cve, client, alert)
            alert_number = report_data.get("alert_number", "ADVISORY")

            os.makedirs(settings.REPORT_OUTPUT_DIR, exist_ok=True)
            docx_filename = f"{alert_number}_advisory.docx"
            docx_path = os.path.join(settings.REPORT_OUTPUT_DIR, docx_filename)
            generate_docx(report_data, client.name, alert_number, docx_path)

            existing = (await db.execute(
                select(Report).where(Report.alert_id == alert.id)
            )).scalar_one_or_none()

            if existing:
                existing.alert_number = alert_number
                existing.report_data  = report_data
                existing.pdf_path     = docx_path
                existing.pdf_filename = docx_filename
                existing.rag_examples_used = rag_filenames
                existing.status       = "draft"
                existing.generated_at = datetime.utcnow()
                db.add(existing)
                report_obj = existing
            else:
                report_obj = Report(
                    alert_id=alert.id, cve_id=cve.id, client_id=client.id,
                    alert_number=alert_number, report_data=report_data,
                    pdf_path=docx_path, pdf_filename=docx_filename,
                    rag_examples_used=rag_filenames,
                )
                db.add(report_obj)

            await db.flush()
            await db.commit()
            await db.refresh(report_obj, ["client"])
            logger.info(f"[AutoPipeline] Report ready: {alert_number}")

            # ── Step 3: Send email ────────────────────────────────────────────
            if client.email:
                try:
                    _send_report_email(report_obj)
                    report_obj.status = "sent"
                    await db.commit()
                    logger.info(f"[AutoPipeline] Email sent: {alert_number} → {client.email}")
                except Exception as e:
                    logger.error(f"[AutoPipeline] Email failed for {alert_number}: {e}")
            else:
                logger.warning(f"[AutoPipeline] No email for {client.name}, saved as draft")

    return _run(_auto())
