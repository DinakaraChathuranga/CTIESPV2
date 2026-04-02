# api/routes.py  ─── All API routes in one file for clarity
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional, List
import os, logging
from datetime import datetime

from core.database import get_db
from models import db_models as M
from models import schemas as S
from services.matching.engine import embed_all_assets
from services.ingestion.normalizer import upsert_cves, NormalizedCVE
from services.reporting.rag_store import (
    add_sample_report,
    list_sample_reports, delete_sample_report
)
from workers.tasks import (
    poll_nvd_task, poll_cisa_task, poll_rss_task,
    poll_epss_task, generate_report_task, embed_assets_task
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# CLIENTS
# ═══════════════════════════════════════════════════════════════════════════════

clients_router = APIRouter(prefix="/clients", tags=["Clients"])


@clients_router.get("", response_model=List[S.ClientOut])
async def list_clients(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(M.Client).order_by(M.Client.name))
    return result.scalars().unique().all()


@clients_router.post("", response_model=S.ClientOut, status_code=201)
async def create_client(body: S.ClientCreate, bg: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    client = M.Client(**body.model_dump())
    db.add(client)
    await db.commit()
    await db.refresh(client)
    return client


@clients_router.get("/{client_id}", response_model=S.ClientOut)
async def get_client(client_id: str, db: AsyncSession = Depends(get_db)):
    c = await db.get(M.Client, client_id)
    if not c:
        raise HTTPException(404, "Client not found")
    return c


@clients_router.put("/{client_id}", response_model=S.ClientOut)
async def update_client(client_id: str, body: S.ClientUpdate, db: AsyncSession = Depends(get_db)):
    c = await db.get(M.Client, client_id)
    if not c:
        raise HTTPException(404, "Client not found")
    for k, v in body.model_dump().items():
        setattr(c, k, v)
    await db.commit()
    await db.refresh(c)
    return c


@clients_router.delete("/{client_id}", status_code=204)
async def delete_client(client_id: str, db: AsyncSession = Depends(get_db)):
    c = await db.get(M.Client, client_id)
    if not c:
        raise HTTPException(404, "Client not found")
    await db.delete(c)
    await db.commit()


@clients_router.put("/{client_id}/assets", response_model=S.ClientOut)
async def set_assets(client_id: str, body: S.AssetsUpdate, bg: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    """Replace the entire asset list for a client. Triggers background embedding."""
    c = await db.get(M.Client, client_id)
    if not c:
        raise HTTPException(404, "Client not found")

    # Delete existing assets
    for asset in list(c.assets):
        await db.delete(asset)

    # Insert new assets
    new_assets = []
    for a in body.assets:
        asset = M.ClientAsset(
            client_id=client_id,
            asset_name=a.asset_name.strip(),
            cpe_string=a.cpe_string,
        )
        db.add(asset)
        new_assets.append(asset)

    await db.commit()
    await db.refresh(c)

    # Compute embeddings in background (fresh session opened inside)
    bg.add_task(_embed_assets_bg, new_assets, None)

    return c


async def _embed_assets_bg(assets: List[M.ClientAsset], _unused_db: AsyncSession):
    """Background: compute and store embeddings for new assets using a fresh session."""
    from services.matching.semantic_matcher import embed, normalize_product
    from core.database import AsyncSessionLocal

    texts = [normalize_product(a.asset_name) for a in assets]
    asset_ids = [a.id for a in assets]
    if not texts:
        return
    try:
        embs = embed(texts)
        async with AsyncSessionLocal() as new_db:
            for asset_id, emb in zip(asset_ids, embs):
                a = await new_db.get(M.ClientAsset, asset_id)
                if a:
                    a.embedding = emb.tolist()
                    new_db.add(a)
            await new_db.commit()
        logger.info(f"Background: embedded {len(texts)} assets")
    except Exception as e:
        logger.error(f"Background embedding failed: {e}", exc_info=True)


# ═══════════════════════════════════════════════════════════════════════════════
# CVEs
# ═══════════════════════════════════════════════════════════════════════════════

cves_router = APIRouter(prefix="/cves", tags=["CVEs"])


def _apply_cve_filters(q, severity, source, is_kev, search):
    if severity:
        q = q.where(M.CVE.severity == severity.upper())
    if source:
        q = q.where(M.CVE.source == source)
    if is_kev is not None:
        q = q.where(M.CVE.is_kev == is_kev)
    if search:
        like = f"%{search}%"
        q = q.where(M.CVE.title.ilike(like) | M.CVE.cve_ids.ilike(like))
    return q


@cves_router.get("", response_model=List[S.CVEOut])
async def list_cves(
    severity: Optional[str] = None,
    source: Optional[str] = None,
    is_kev: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    q = _apply_cve_filters(select(M.CVE), severity, source, is_kev, search)
    q = q.order_by(desc(M.CVE.priority_score), desc(M.CVE.date_added)).limit(limit).offset(offset)
    result = await db.execute(q)
    return result.scalars().all()


@cves_router.get("/count")
async def count_cves(
    severity: Optional[str] = None,
    source: Optional[str] = None,
    is_kev: Optional[bool] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """Return total count of CVEs matching the given filters (for pagination)."""
    q = _apply_cve_filters(select(func.count(M.CVE.id)), severity, source, is_kev, search)
    total = await db.scalar(q)
    return {"total": total or 0}


@cves_router.post("", response_model=dict, status_code=201)
async def ingest_cve_manual(body: S.CVECreate, db: AsyncSession = Depends(get_db)):
    """Manually ingest a CVE and run asset matching immediately."""
    norm = NormalizedCVE(
        cve_ids=body.cve_ids,
        title=body.title,
        vuln_type=body.vuln_type or "",
        severity=body.severity,
        cvss_score=body.cvss_score,
        affected_products=body.affected_products,
        cpe_strings=body.cpe_strings,
        description=body.description or "",
        impact=body.impact,
        attack_vector=body.attack_vector,
        remediation=body.remediation or "",
        refs=body.refs,
        vendor_advisory=body.vendor_advisory,
        source="manual",
    )
    new_count, _ = await upsert_cves([norm], db)
    if not new_count:
        raise HTTPException(409, f"CVE {body.cve_ids} already exists")

    result = await db.execute(select(M.CVE).where(M.CVE.cve_ids == body.cve_ids))
    cve = result.scalar_one_or_none()
    if not cve:
        raise HTTPException(500, "CVE creation failed")

    from services.matching.alert_factory import create_alerts_for_cve
    alerts_created, match_summaries = await create_alerts_for_cve(cve, db)
    matched_clients = [m["client_name"] for m in match_summaries]

    return {
        "cve_id":          cve.id,
        "cve_ids":         cve.cve_ids,
        "alerts_created":  alerts_created,
        "matched_clients": matched_clients,
    }


@cves_router.get("/{cve_id}", response_model=S.CVEOut)
async def get_cve(cve_id: str, db: AsyncSession = Depends(get_db)):
    cve = await db.get(M.CVE, cve_id)
    if not cve:
        raise HTTPException(404, "CVE not found")
    return cve


@cves_router.delete("/{cve_id}", status_code=204)
async def delete_cve(cve_id: str, db: AsyncSession = Depends(get_db)):
    cve = await db.get(M.CVE, cve_id)
    if not cve:
        raise HTTPException(404, "CVE not found")
    await db.delete(cve)
    await db.commit()


@cves_router.post("/poll/{source}")
async def trigger_poll(source: str):
    """Manually trigger a CVE feed poll."""
    task_map = {
        "nvd":  poll_nvd_task,
        "cisa": poll_cisa_task,
        "rss":  poll_rss_task,
        "epss": poll_epss_task,
        "all":  None,
    }
    if source not in task_map:
        raise HTTPException(400, f"Unknown source. Use: {list(task_map.keys())}")

    if source == "all":
        for task in [poll_nvd_task, poll_cisa_task, poll_rss_task]:
            task.delay()
        return {"status": "triggered", "sources": ["nvd", "cisa", "rss"]}

    task_map[source].delay()
    return {"status": "triggered", "source": source}


# ═══════════════════════════════════════════════════════════════════════════════
# ALERTS
# ═══════════════════════════════════════════════════════════════════════════════

alerts_router = APIRouter(prefix="/alerts", tags=["Alerts"])


@alerts_router.get("", response_model=List[S.AlertOut])
async def list_alerts(
    status: Optional[str] = None,
    client_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    q = select(M.Alert)
    if status:
        q = q.where(M.Alert.status == status)
    if client_id:
        q = q.where(M.Alert.client_id == client_id)
    q = q.order_by(desc(M.Alert.created_at))
    result = await db.execute(q)
    return result.scalars().unique().all()


@alerts_router.get("/stats", response_model=dict)
async def alert_stats(db: AsyncSession = Depends(get_db)):
    for status in ("pending", "approved", "rejected"):
        pass
    rows = await db.execute(
        select(M.Alert.status, func.count(M.Alert.id))
        .group_by(M.Alert.status)
    )
    stats = {r[0]: r[1] for r in rows}
    return {
        "pending":  stats.get("pending", 0),
        "approved": stats.get("approved", 0),
        "rejected": stats.get("rejected", 0),
        "total":    sum(stats.values()),
    }


@alerts_router.get("/{alert_id}", response_model=S.AlertOut)
async def get_alert(alert_id: str, db: AsyncSession = Depends(get_db)):
    alert = await db.get(M.Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return alert


@alerts_router.patch("/{alert_id}", response_model=dict)
async def action_alert(
    alert_id: str,
    body: S.AlertAction,
    bg: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """
    Approve or reject an alert.
    On approval → triggers async report generation via Celery.
    """
    alert = await db.get(M.Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")

    alert.status = body.status
    alert.reviewed_at = datetime.utcnow()
    alert.reviewed_by = body.reviewed_by
    if body.notes:
        alert.notes = body.notes

    await db.commit()

    task_id = None
    if body.status == "approved":
        task = generate_report_task.delay(alert_id)
        task_id = task.id
        logger.info(f"[API] Report generation queued for alert {alert_id}, task={task_id}")

    return {
        "alert_id": alert_id,
        "status": body.status,
        "report_task_id": task_id,
        "message": "Report generation started — check /reports in a few seconds" if task_id else "Alert rejected",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# REPORTS
# ═══════════════════════════════════════════════════════════════════════════════

reports_router = APIRouter(prefix="/reports", tags=["Reports"])


@reports_router.get("", response_model=List[S.ReportOut])
async def list_reports(
    status: Optional[str] = None,
    client_id: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    q = select(M.Report)
    if status:
        q = q.where(M.Report.status == status)
    if client_id:
        q = q.where(M.Report.client_id == client_id)
    q = q.order_by(desc(M.Report.generated_at))
    result = await db.execute(q)
    return result.scalars().unique().all()


@reports_router.get("/{report_id}", response_model=S.ReportOut)
async def get_report(report_id: str, db: AsyncSession = Depends(get_db)):
    r = await db.get(M.Report, report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    return r


@reports_router.get("/{report_id}/pdf")
async def download_pdf(report_id: str, db: AsyncSession = Depends(get_db)):
    r = await db.get(M.Report, report_id)
    if not r or not r.pdf_path:
        raise HTTPException(404, "Report file not found")
    if not os.path.exists(r.pdf_path):
        raise HTTPException(404, "Report file missing from disk")
    filename = r.pdf_filename or f"{r.alert_number}.html"
    media_type = "text/html" if filename.endswith(".html") else "application/pdf"
    return FileResponse(r.pdf_path, media_type=media_type, filename=filename)


@reports_router.post("/{report_id}/send", response_model=dict)
async def send_report(report_id: str, db: AsyncSession = Depends(get_db)):
    """Mark a report as sent (email integration is Phase 2)."""
    r = await db.get(M.Report, report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    r.status = "sent"
    r.sent_at = datetime.utcnow()
    await db.commit()
    return {"ok": True, "sent_at": r.sent_at.isoformat(), "report_id": report_id}


@reports_router.post("/{report_id}/regenerate", response_model=dict)
async def regenerate_report(report_id: str, db: AsyncSession = Depends(get_db)):
    """Re-trigger report generation for an existing report."""
    r = await db.get(M.Report, report_id)
    if not r:
        raise HTTPException(404, "Report not found")
    task = generate_report_task.delay(r.alert_id)
    return {"task_id": task.id, "message": "Regeneration started"}


# ═══════════════════════════════════════════════════════════════════════════════
# SAMPLE REPORTS (RAG store management)
# ═══════════════════════════════════════════════════════════════════════════════

samples_router = APIRouter(prefix="/sample-reports", tags=["Sample Reports"])


@samples_router.get("")
async def list_samples(db: AsyncSession = Depends(get_db)):
    """List all sample reports indexed in ChromaDB."""
    return await list_sample_reports()


@samples_router.post("/upload", status_code=201)
async def upload_sample_report(
    file: UploadFile = File(...),
    severity: Optional[str] = None,
    vuln_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Upload a sample advisory report (PDF or TXT) to the RAG vector store.
    The report's writing style will be used as a reference for future AI generation.
    """
    content = await file.read()
    filename = file.filename or "unnamed"
    text = ""

    if filename.lower().endswith(".pdf"):
        # Extract text from PDF
        try:
            import pdfplumber
            import io
            with pdfplumber.open(io.BytesIO(content)) as pdf:
                text = "\n\n".join(
                    (page.extract_text() or "") for page in pdf.pages
                )
        except ImportError:
            # Fallback: try PyPDF2
            try:
                import PyPDF2, io
                reader = PyPDF2.PdfReader(io.BytesIO(content))
                text = "\n\n".join(
                    (page.extract_text() or "") for page in reader.pages
                )
            except Exception as e:
                raise HTTPException(400, f"PDF parsing failed: {e}. Upload a .txt file instead.")
    elif filename.lower().endswith((".txt", ".md")):
        text = content.decode("utf-8", errors="replace")
    else:
        raise HTTPException(400, "Only PDF, TXT, or MD files are supported")

    if len(text.strip()) < 100:
        raise HTTPException(400, "Could not extract enough text from the file (min 100 chars)")

    doc_id = await add_sample_report(
        text=text,
        filename=filename,
        severity=severity,
        vuln_type=vuln_type,
    )

    # Store in DB too
    sample = M.SampleReport(
        filename=filename,
        severity=severity,
        vuln_type=vuln_type,
        full_text=text[:5000],
        chroma_doc_id=doc_id,
    )
    db.add(sample)
    await db.commit()

    return {"ok": True, "doc_id": doc_id, "filename": filename, "chars_indexed": len(text)}


@samples_router.delete("/{doc_id}", status_code=204)
async def delete_sample(doc_id: str, db: AsyncSession = Depends(get_db)):
    deleted = await delete_sample_report(doc_id)
    if not deleted:
        raise HTTPException(404, "Sample report not found")
    # Remove from DB
    result = await db.execute(
        select(M.SampleReport).where(M.SampleReport.chroma_doc_id == doc_id)
    )
    s = result.scalar_one_or_none()
    if s:
        await db.delete(s)
        await db.commit()


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM / HEALTH
# ═══════════════════════════════════════════════════════════════════════════════

system_router = APIRouter(prefix="/system", tags=["System"])


@system_router.get("/health", response_model=S.HealthOut)
async def health_check(db: AsyncSession = Depends(get_db)):
    db_ok = False
    redis_ok = False
    chroma_ok = False
    model_ok = False

    try:
        await db.execute(select(func.now()))
        db_ok = True
    except Exception:
        pass

    try:
        import redis
        r = redis.from_url(settings_ref().REDIS_URL)
        r.ping()
        redis_ok = True
    except Exception:
        pass

    try:
        import httpx
        r = httpx.get(f"http://chromadb:{settings_ref().CHROMA_PORT}/api/v1/heartbeat", timeout=3)
        chroma_ok = r.status_code == 200
    except Exception:
        pass

    try:
        from services.matching.semantic_matcher import get_model
        get_model()
        model_ok = True
    except Exception:
        pass

    return S.HealthOut(
        status="ok" if all([db_ok, model_ok]) else "degraded",
        db=db_ok, redis=redis_ok, chromadb=chroma_ok,
        embedding_model_loaded=model_ok,
    )


def settings_ref():
    from core.config import settings
    return settings


@system_router.get("/stats", response_model=S.DashboardStats)
async def dashboard_stats(db: AsyncSession = Depends(get_db)):
    async def count(model, **filters):
        q = select(func.count(model.id))
        for k, v in filters.items():
            q = q.where(getattr(model, k) == v)
        r = await db.execute(q)
        return r.scalar_one()

    async def last_poll(source: str):
        r = await db.execute(
            select(M.PollLog.run_at)
            .where(M.PollLog.source == source, M.PollLog.error.is_(None))
            .order_by(desc(M.PollLog.run_at)).limit(1)
        )
        return r.scalar_one_or_none()

    return S.DashboardStats(
        clients=await count(M.Client),
        cves=await count(M.CVE),
        alerts_pending=await count(M.Alert, status="pending"),
        alerts_total=await db.scalar(select(func.count(M.Alert.id))),
        reports_draft=await count(M.Report, status="draft"),
        reports_sent=await count(M.Report, status="sent"),
        critical_cves=await count(M.CVE, severity="CRITICAL"),
        kev_cves=await db.scalar(select(func.count(M.CVE.id)).where(M.CVE.is_kev == True)),
        last_poll_nvd=await last_poll("nvd"),
        last_poll_cisa=await last_poll("cisa_kev"),
        last_poll_rss=await last_poll("rss"),
    )


@system_router.post("/embed-assets")
async def trigger_embed():
    """Trigger batch embedding of all assets without embeddings."""
    embed_assets_task.delay()
    return {"status": "triggered"}
