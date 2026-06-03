# api/routes.py
import asyncio
import logging
import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape
from typing import Optional, List

import httpx
import redis
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, UploadFile, File
from fastapi.responses import FileResponse
from sqlalchemy import desc, func, select, cast, String, or_
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import require_admin, require_reader
from core.config import settings
from core.database import get_db
from models import db_models as M
from models import schemas as S
from services.ingestion.normalizer import NormalizedCVE, upsert_cves
from services.reporting.rag_store import add_sample_report
from workers.tasks import (
    embed_assets_task,
    generate_report_task,
    poll_cisa_task,
    poll_epss_task,
    poll_nvd_task,
    poll_rss_task,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Helper functions
# ═══════════════════════════════════════════════════════════════════════════════

def _safe_score(score) -> float:
    try:
        return round(max(0.0, min(float(score or 0), 1.0)), 4)
    except Exception:
        return 0.0


def _append_note(existing: Optional[str], new_note: str) -> str:
    if existing:
        return f"{new_note}\n\n{existing}"
    return new_note


def _get_optional_attr(obj, attr: str, default=None):
    return getattr(obj, attr, default)


# ═══════════════════════════════════════════════════════════════════════════════
# CLIENTS
# ═══════════════════════════════════════════════════════════════════════════════

clients_router = APIRouter(prefix="/clients", tags=["Clients"])


@clients_router.get("", response_model=List[S.ClientOut])
async def list_clients(
    search: Optional[str] = None,
    _: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    """
    List clients.

    Optional search checks:
    - client name
    - company
    - email
    - asset name
    - CPE string
    """
    q = select(M.Client)

    if search:
        like = f"%{search.strip()}%"
        q = (
            q.join(M.Client.assets, isouter=True)
            .where(
                or_(
                    M.Client.name.ilike(like),
                    M.Client.email.ilike(like),
                    M.Client.company.ilike(like),
                    M.ClientAsset.asset_name.ilike(like),
                    M.ClientAsset.cpe_string.ilike(like),
                )
            )
        )

    q = q.order_by(M.Client.name)
    result = await db.execute(q)
    return result.scalars().unique().all()


@clients_router.post("", response_model=S.ClientOut, status_code=201)
async def create_client(
    body: S.ClientCreate,
    _: M.User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    client = M.Client(**body.model_dump())
    db.add(client)
    await db.commit()
    await db.refresh(client)
    return client


@clients_router.get("/{client_id}", response_model=S.ClientOut)
async def get_client(
    client_id: str,
    _: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    client = await db.get(M.Client, client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


@clients_router.put("/{client_id}", response_model=S.ClientOut)
async def update_client(
    client_id: str,
    body: S.ClientUpdate,
    _: M.User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    client = await db.get(M.Client, client_id)
    if not client:
        raise HTTPException(404, "Client not found")

    for key, value in body.model_dump().items():
        setattr(client, key, value)

    await db.commit()
    await db.refresh(client)
    return client


@clients_router.delete("/{client_id}", status_code=204)
async def delete_client(
    client_id: str,
    _: M.User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    client = await db.get(M.Client, client_id)
    if not client:
        raise HTTPException(404, "Client not found")

    await db.delete(client)
    await db.commit()


@clients_router.put("/{client_id}/assets", response_model=S.ClientOut)
async def set_assets(
    client_id: str,
    body: S.AssetsUpdate,
    bg: BackgroundTasks,
    _: M.User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    Replace full asset list for a client.

    Only security_admin can add/edit/remove assets.
    """
    client = await db.get(M.Client, client_id)
    if not client:
        raise HTTPException(404, "Client not found")

    for asset in list(client.assets):
        await db.delete(asset)

    new_assets = []
    for item in body.assets:
        asset_name = item.asset_name.strip()
        if not asset_name:
            continue

        asset = M.ClientAsset(
            client_id=client_id,
            asset_name=asset_name,
            cpe_string=item.cpe_string,
        )
        db.add(asset)
        new_assets.append(asset)

    await db.commit()
    await db.refresh(client)

    bg.add_task(_embed_assets_bg, new_assets)
    return client


async def _embed_assets_bg(assets: List[M.ClientAsset]):
    """Background: compute and store embeddings for new assets."""
    from services.matching.semantic_matcher import embed, normalize_product
    from core.database import AsyncSessionLocal

    if not assets:
        return

    texts = [normalize_product(asset.asset_name) for asset in assets]
    asset_ids = [asset.id for asset in assets]

    try:
        embeddings = embed(texts)

        async with AsyncSessionLocal() as db:
            for asset_id, embedding in zip(asset_ids, embeddings):
                asset = await db.get(M.ClientAsset, asset_id)
                if asset:
                    asset.embedding = embedding.tolist()
                    db.add(asset)

            await db.commit()

        logger.info("Background embedded %d assets", len(texts))

    except Exception as e:
        logger.error("Background asset embedding failed: %s", e, exc_info=True)


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
        like = f"%{search.strip()}%"
        q = q.where(
            or_(
                M.CVE.title.ilike(like),
                M.CVE.cve_ids.ilike(like),
                M.CVE.description.ilike(like),
                cast(M.CVE.affected_products, String).ilike(like),
                cast(M.CVE.cpe_strings, String).ilike(like),
            )
        )

    return q


@cves_router.get("", response_model=List[S.CVEOut])
async def list_cves(
    severity: Optional[str] = None,
    source: Optional[str] = None,
    is_kev: Optional[bool] = None,
    search: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: M.User = Depends(require_reader),
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
    _: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    q = _apply_cve_filters(select(func.count(M.CVE.id)), severity, source, is_kev, search)
    total = await db.scalar(q)
    return {"total": total or 0}


@cves_router.post("", response_model=dict, status_code=201)
async def ingest_cve_manual(
    body: S.CVECreate,
    _: M.User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    Manually ingest a CVE.

    Normal path:
    - Create/update CVE.
    - Run matching engine.
    - Create alerts for matched clients.

    Direct path:
    - If direct_client_id is provided, bypass matching engine.
    - Create alert directly for selected client and asset.
    """
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

    result = await db.execute(select(M.CVE).where(M.CVE.cve_ids == body.cve_ids))
    cve = result.scalar_one_or_none()

    if not cve:
        raise HTTPException(500, "CVE creation failed")

    direct_client_id = getattr(body, "direct_client_id", None)
    direct_asset_name = getattr(body, "direct_asset_name", None)

    if direct_client_id:
        client = await db.get(M.Client, direct_client_id)
        if not client:
            raise HTTPException(404, "Selected client not found")

        existing_alert = await db.execute(
            select(M.Alert).where(
                M.Alert.cve_id == cve.id,
                M.Alert.client_id == client.id,
            )
        )
        existing = existing_alert.scalar_one_or_none()

        if existing:
            return {
                "cve_id": cve.id,
                "cve_ids": cve.cve_ids,
                "is_new_cve": new_count > 0,
                "alerts_created": 0,
                "matched_clients": [client.name],
                "message": f"Alert already exists for {client.name}",
            }

        asset_list = [direct_asset_name.strip()] if direct_asset_name else []

        alert = M.Alert(
            cve_id=cve.id,
            client_id=client.id,
            match_method="manual",
            match_score=1.0,
            matched_assets=asset_list,
            matched_cpes=[],
        )

        optional_values = {
            "raw_match_score": 1.0,
            "boosted_match_score": 1.0,
            "match_decision": "manual_confirmed",
            "match_reason": "Manually selected by analyst during CVE ingest.",
        }

        for field, value in optional_values.items():
            if hasattr(alert, field):
                setattr(alert, field, value)

        db.add(alert)
        await db.commit()

        logger.info(
            "[CVE Manual] Direct alert created: %s -> %s asset=%s",
            cve.cve_ids,
            client.name,
            direct_asset_name,
        )

        return {
            "cve_id": cve.id,
            "cve_ids": cve.cve_ids,
            "is_new_cve": new_count > 0,
            "alerts_created": 1,
            "matched_clients": [client.name],
            "message": "Manual client alert created successfully",
        }

    if not new_count:
        raise HTTPException(409, f"CVE {body.cve_ids} already exists")

    from services.matching.alert_factory import create_alerts_for_cve

    alerts_created, match_summaries = await create_alerts_for_cve(cve, db)

    return {
        "cve_id": cve.id,
        "cve_ids": cve.cve_ids,
        "is_new_cve": new_count > 0,
        "alerts_created": alerts_created,
        "matched_clients": [item["client_name"] for item in match_summaries],
    }


@cves_router.get("/{cve_id}", response_model=S.CVEOut)
async def get_cve(
    cve_id: str,
    _: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    cve = await db.get(M.CVE, cve_id)
    if not cve:
        raise HTTPException(404, "CVE not found")
    return cve


@cves_router.delete("/{cve_id}", status_code=204)
async def delete_cve(
    cve_id: str,
    _: M.User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    cve = await db.get(M.CVE, cve_id)
    if not cve:
        raise HTTPException(404, "CVE not found")

    await db.delete(cve)
    await db.commit()


@cves_router.post("/poll/{source}")
async def trigger_poll(
    source: str,
    _: M.User = Depends(require_reader),
):
    task_map = {
        "nvd": poll_nvd_task,
        "cisa": poll_cisa_task,
        "rss": poll_rss_task,
        "epss": poll_epss_task,
    }

    if source == "all":
        for task in [poll_nvd_task, poll_cisa_task, poll_rss_task]:
            task.delay()

        return {
            "status": "triggered",
            "sources": ["nvd", "cisa", "rss"],
        }

    if source not in task_map:
        raise HTTPException(400, f"Unknown source. Use: {list(task_map.keys()) + ['all']}")

    task_map[source].delay()
    return {"status": "triggered", "source": source}


# ═══════════════════════════════════════════════════════════════════════════════
# ALERTS
# ═══════════════════════════════════════════════════════════════════════════════

alerts_router = APIRouter(prefix="/alerts", tags=["Alerts"])


@alerts_router.get("/stats", response_model=dict)
async def alert_stats(
    _: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    rows = await db.execute(
        select(M.Alert.status, func.count(M.Alert.id)).group_by(M.Alert.status)
    )

    stats = {row[0]: row[1] for row in rows}

    return {
        "pending": stats.get("pending", 0),
        "approved": stats.get("approved", 0),
        "rejected": stats.get("rejected", 0),
        "total": sum(stats.values()),
    }


@alerts_router.get("/grouped")
async def grouped_alerts(
    status: Optional[str] = None,
    search: Optional[str] = None,
    severity: Optional[str] = None,
    min_score: Optional[float] = Query(None, ge=0, le=1),
    kev_only: Optional[bool] = None,
    _: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    """
    Return alerts grouped by CVE.

    This keeps current DB design but gives analysts one CVE group with all
    affected customers/assets.
    """
    q = select(M.Alert).join(M.Alert.cve, isouter=True).join(M.Alert.client, isouter=True)

    if status:
        q = q.where(M.Alert.status == status)

    if severity:
        q = q.where(M.CVE.severity == severity.upper())

    if min_score is not None:
        q = q.where(M.Alert.match_score >= min_score)

    if kev_only is not None:
        q = q.where(M.CVE.is_kev == kev_only)

    if search:
        like = f"%{search.strip()}%"
        q = q.where(
            or_(
                M.CVE.cve_ids.ilike(like),
                M.CVE.title.ilike(like),
                M.Client.name.ilike(like),
                cast(M.Alert.matched_assets, String).ilike(like),
                cast(M.Alert.notes, String).ilike(like),
            )
        )

    q = q.order_by(desc(M.Alert.created_at))

    result = await db.execute(q)
    alerts = result.scalars().unique().all()

    groups = {}

    for alert in alerts:
        cve = alert.cve
        client = alert.client
        key = alert.cve_id

        if key not in groups:
            groups[key] = {
                "cve_id": key,
                "cve_ids": cve.cve_ids if cve else "Unknown",
                "title": cve.title if cve else "",
                "severity": cve.severity if cve else "UNKNOWN",
                "cvss_score": cve.cvss_score if cve else None,
                "priority_score": cve.priority_score if cve else None,
                "is_kev": cve.is_kev if cve else False,
                "counts": {
                    "pending": 0,
                    "approved": 0,
                    "rejected": 0,
                },
                "alerts": [],
            }

        groups[key]["counts"][alert.status] = groups[key]["counts"].get(alert.status, 0) + 1

        groups[key]["alerts"].append(
            {
                "id": alert.id,
                "status": alert.status,
                "client_id": alert.client_id,
                "client_name": client.name if client else "Unknown",
                "client_email": client.email if client else "",
                "matched_assets": alert.matched_assets or [],
                "matched_cpes": alert.matched_cpes or [],
                "match_method": alert.match_method,
                "match_score": _safe_score(alert.match_score),
                "raw_match_score": _get_optional_attr(alert, "raw_match_score"),
                "boosted_match_score": _get_optional_attr(alert, "boosted_match_score"),
                "match_decision": _get_optional_attr(alert, "match_decision"),
                "match_reason": _get_optional_attr(alert, "match_reason"),
                "ai_verdict": _get_optional_attr(alert, "ai_verdict"),
                "ai_confidence": _get_optional_attr(alert, "ai_confidence"),
                "ai_reason": _get_optional_attr(alert, "ai_reason"),
                "ai_recommended_action": _get_optional_attr(alert, "ai_recommended_action"),
                "ai_verified_at": (
                    _get_optional_attr(alert, "ai_verified_at").isoformat()
                    if _get_optional_attr(alert, "ai_verified_at")
                    else None
                ),
                "ai_verified_by": _get_optional_attr(alert, "ai_verified_by"),
                "created_at": alert.created_at.isoformat() if alert.created_at else None,
                "reviewed_at": alert.reviewed_at.isoformat() if alert.reviewed_at else None,
                "reviewed_by": alert.reviewed_by,
                "notes": alert.notes,
            }
        )

    grouped = list(groups.values())
    grouped.sort(
        key=lambda item: (
            item["counts"].get("pending", 0),
            item.get("priority_score") or 0,
        ),
        reverse=True,
    )

    return grouped


@alerts_router.get("", response_model=List[S.AlertOut])
async def list_alerts(
    status: Optional[str] = None,
    client_id: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    asset: Optional[str] = None,
    match_method: Optional[str] = None,
    min_score: Optional[float] = Query(None, ge=0, le=1),
    kev_only: Optional[bool] = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    """
    Searchable alert queue.
    """
    q = select(M.Alert).join(M.Alert.cve, isouter=True).join(M.Alert.client, isouter=True)

    if status:
        q = q.where(M.Alert.status == status)

    if client_id:
        q = q.where(M.Alert.client_id == client_id)

    if severity:
        q = q.where(M.CVE.severity == severity.upper())

    if match_method:
        q = q.where(M.Alert.match_method == match_method)

    if min_score is not None:
        q = q.where(M.Alert.match_score >= min_score)

    if kev_only is not None:
        q = q.where(M.CVE.is_kev == kev_only)

    if search:
        like = f"%{search.strip()}%"
        q = q.where(
            or_(
                M.CVE.cve_ids.ilike(like),
                M.CVE.title.ilike(like),
                M.CVE.description.ilike(like),
                M.Client.name.ilike(like),
                M.Client.email.ilike(like),
                cast(M.Alert.matched_assets, String).ilike(like),
                cast(M.Alert.matched_cpes, String).ilike(like),
                cast(M.Alert.notes, String).ilike(like),
            )
        )

    if asset:
        like_asset = f"%{asset.strip()}%"
        q = q.where(cast(M.Alert.matched_assets, String).ilike(like_asset))

    q = q.order_by(desc(M.Alert.created_at)).limit(limit).offset(offset)

    result = await db.execute(q)
    return result.scalars().unique().all()


@alerts_router.post("/bulk-approve")
async def bulk_approve_alerts(
    body: S.BulkApproveRequest,
    current_user: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    """
    Approve multiple alerts and queue report generation for each.
    """
    approved_ids = []

    for alert_id in body.alert_ids:
        alert = await db.get(M.Alert, alert_id)

        if not alert or alert.status != "pending":
            continue

        alert.status = "approved"
        alert.reviewed_at = datetime.utcnow()
        alert.reviewed_by = current_user.username

        if body.notes:
            alert.notes = _append_note(alert.notes, body.notes)

        approved_ids.append(alert_id)

    await db.commit()

    task_ids = []
    for alert_id in approved_ids:
        task = generate_report_task.delay(alert_id)
        task_ids.append(task.id)

    logger.info("[Alerts] Bulk approved %d alerts by %s", len(approved_ids), current_user.username)

    return {
        "approved": len(approved_ids),
        "task_ids": task_ids,
        "message": f"{len(approved_ids)} reports queued for generation",
    }


@alerts_router.get("/{alert_id}", response_model=S.AlertOut)
async def get_alert(
    alert_id: str,
    _: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    alert = await db.get(M.Alert, alert_id)

    if not alert:
        raise HTTPException(404, "Alert not found")

    return alert


@alerts_router.patch("/{alert_id}", response_model=dict)
async def action_alert(
    alert_id: str,
    body: S.AlertAction,
    bg: BackgroundTasks,
    current_user: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    """
    Approve, reject, or restore an alert.

    AI verdict never auto-approves or auto-rejects.
    The analyst still makes the final action here.
    """
    alert = await db.get(M.Alert, alert_id)

    if not alert:
        raise HTTPException(404, "Alert not found")

    previous_status = alert.status

    alert.status = body.status
    alert.reviewed_at = datetime.utcnow()
    alert.reviewed_by = current_user.username

    if body.notes:
        alert.notes = _append_note(alert.notes, body.notes)

    if body.status == "rejected":
        alert.declined_at = datetime.utcnow()
        alert.restored_at = None

    elif body.status == "pending" and previous_status == "rejected":
        alert.restored_at = datetime.utcnow()
        alert.declined_at = None

    await db.commit()

    task_id = None

    if body.status == "approved":
        task = generate_report_task.delay(alert_id)
        task_id = task.id
        logger.info("[API] Report generation queued for alert %s task=%s", alert_id, task_id)

    msg_map = {
        "approved": "Report generation started — check Reports in a few seconds",
        "rejected": "Alert moved to archive",
        "pending": "Alert restored to pending queue",
    }

    return {
        "alert_id": alert_id,
        "status": body.status,
        "report_task_id": task_id,
        "message": msg_map.get(body.status, "Done"),
    }


@alerts_router.post("/{alert_id}/verify")
async def ai_verify_alert(
    alert_id: str,
    current_user: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    """
    Manual AI verification.

    This does NOT approve or reject automatically.
    It only stores AI verdict, confidence, reason, and recommendation.
    """
    alert = await db.get(M.Alert, alert_id)

    if not alert:
        raise HTTPException(404, "Alert not found")

    if alert.status != "pending":
        raise HTTPException(400, f"Only pending alerts can be verified. Current status: {alert.status}")

    score = _safe_score(alert.match_score)

    if score < 0.80 and alert.match_method != "manual":
        raise HTTPException(
            400,
            f"AI verification requires match score >= 80%. Current score is {score * 100:.0f}%.",
        )

    cve = alert.cve
    client = alert.client

    if not cve or not client:
        raise HTTPException(400, "Alert is missing CVE or client details")

    matched_assets = alert.matched_assets or []
    asset_name = matched_assets[0] if matched_assets else "Unknown asset"

    from services.matching.verifier import verify_cve_asset_match

    result = await verify_cve_asset_match(
        cve_id=cve.cve_ids,
        title=cve.title or "",
        description=cve.description or "",
        affected_products=cve.affected_products or [],
        cpe_strings=cve.cpe_strings or [],
        vuln_type=cve.vuln_type or "",
        asset_name=asset_name,
        client_name=client.name,
        match_method=alert.match_method or "",
        match_score=score,
    )

    verdict = result.get("verdict")
    confidence = result.get("confidence")
    reason = result.get("reason")
    recommended_action = result.get("recommended_action")

    optional_values = {
        "ai_verdict": verdict,
        "ai_confidence": confidence,
        "ai_reason": reason,
        "ai_recommended_action": recommended_action,
        "ai_verified_at": datetime.utcnow(),
        "ai_verified_by": current_user.username,
        "ai_model": settings.OPENAI_MODEL,
    }

    for field, value in optional_values.items():
        if hasattr(alert, field):
            setattr(alert, field, value)

    ai_note = (
        f"[AI Verification: {verdict}] "
        f"Confidence: {round(float(confidence or 0) * 100)}%. "
        f"Reason: {reason}. "
        f"Recommended Action: {recommended_action}"
    )

    alert.notes = _append_note(alert.notes, ai_note)

    await db.commit()

    logger.info(
        "[AI Verify] alert=%s cve=%s client=%s asset=%s verdict=%s",
        alert.id,
        cve.cve_ids,
        client.name,
        asset_name,
        verdict,
    )

    return {
        "alert_id": alert.id,
        "status": alert.status,
        "asset_checked": asset_name,
        "verdict": verdict,
        "confidence": confidence,
        "reason": reason,
        "recommended_action": recommended_action,
        "message": "AI verification completed. Analyst must manually approve or reject the alert.",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# REPORTS
# ═══════════════════════════════════════════════════════════════════════════════

reports_router = APIRouter(prefix="/reports", tags=["Reports"])


@reports_router.get("", response_model=List[S.ReportOut])
async def list_reports(
    status: Optional[str] = None,
    client_id: Optional[str] = None,
    search: Optional[str] = None,
    _: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    q = select(M.Report).join(M.Report.cve, isouter=True).join(M.Report.client, isouter=True)

    if status:
        q = q.where(M.Report.status == status)

    if client_id:
        q = q.where(M.Report.client_id == client_id)

    if search:
        like = f"%{search.strip()}%"
        q = q.where(
            or_(
                M.Report.alert_number.ilike(like),
                M.CVE.cve_ids.ilike(like),
                M.CVE.title.ilike(like),
                M.Client.name.ilike(like),
            )
        )

    q = q.order_by(desc(M.Report.generated_at))

    result = await db.execute(q)
    return result.scalars().unique().all()


@reports_router.get("/{report_id}", response_model=S.ReportOut)
async def get_report(
    report_id: str,
    _: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    report = await db.get(M.Report, report_id)

    if not report:
        raise HTTPException(404, "Report not found")

    return report


@reports_router.get("/{report_id}/pdf")
async def download_pdf(
    report_id: str,
    _: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    """
    Existing route name is /pdf, but current output is DOCX.
    Kept for frontend compatibility.
    """
    report = await db.get(M.Report, report_id)

    if not report or not report.pdf_path:
        raise HTTPException(404, "Report file not found")

    if not os.path.exists(report.pdf_path):
        raise HTTPException(404, "Report file missing from disk")

    filename = report.pdf_filename or f"{report.alert_number}.docx"

    if not filename.endswith(".docx"):
        filename = filename.replace(".pdf", ".docx").replace(".html", ".docx")

    return FileResponse(
        report.pdf_path,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        filename=filename,
    )


@reports_router.post("/{report_id}/send", response_model=dict)
async def send_report(
    report_id: str,
    current_user: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    """
    Send report via SMTP.

    Note:
    This keeps your current behaviour but only marks as sent if SMTP succeeds.
    """
    report = await db.get(M.Report, report_id)

    if not report:
        raise HTTPException(404, "Report not found")

    if not settings.SMTP_USER or not settings.SMTP_PASS:
        raise HTTPException(400, "SMTP is not configured")

    if not report.client or not report.client.email:
        raise HTTPException(400, "Client email missing")

    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _send_report_email, report)

        report.status = "sent"
        report.sent_at = datetime.utcnow()
        await db.commit()

        logger.info(
            "[Email] Report %s sent to %s by %s",
            report.alert_number,
            report.client.email,
            current_user.username,
        )

        return {
            "ok": True,
            "sent_at": report.sent_at.isoformat(),
            "report_id": report_id,
            "email_sent": True,
            "email_error": None,
        }

    except Exception as e:
        logger.error("[Email] Failed to send report %s: %s", report_id, e, exc_info=True)
        raise HTTPException(500, f"Email send failed: {e}")


@reports_router.post("/{report_id}/regenerate", response_model=dict)
async def regenerate_report(
    report_id: str,
    _: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    report = await db.get(M.Report, report_id)

    if not report:
        raise HTTPException(404, "Report not found")

    task = generate_report_task.delay(report.alert_id)

    return {
        "status": "queued",
        "report_id": report_id,
        "alert_id": report.alert_id,
        "task_id": task.id,
    }


def _send_report_email(report: M.Report) -> None:
    import msal
    import json
    import urllib.request
    import urllib.error

    data        = report.report_data or {}
    client_name = report.client.name if report.client else "Client"
    subject     = f"[CTI Advisory] {data.get('title', report.alert_number)} — {data.get('severity', 'HIGH')}"
    html_body   = _build_email_html(data, report.alert_number, client_name)

    app = msal.ConfidentialClientApplication(
        settings.SMTP_CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{settings.SMTP_TENANT_ID}",
        client_credential=settings.SMTP_CLIENT_SECRET,
    )
    result = app.acquire_token_for_client(
        scopes=["https://graph.microsoft.com/.default"]
    )
    if "access_token" not in result:
        raise RuntimeError(f"OAuth2 token error: {result.get('error_description', result)}")

    client_email = report.client.email if report.client else None
    if not client_email:
        raise RuntimeError("Client has no email address configured")

    recipients = [
        {"emailAddress": {"address": addr.strip()}}
        for addr in client_email.split(",")
        if addr.strip()
    ]

    email_payload = {
        "message": {
            "subject": subject,
            "body": {
                "contentType": "HTML",
                "content": html_body,
            },
            "toRecipients": recipients,
        }
    }

    url     = f"https://graph.microsoft.com/v1.0/users/{settings.SMTP_USER}/sendMail"
    headers = {
        "Authorization": f"Bearer {result['access_token']}",
        "Content-Type":  "application/json",
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(email_payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        urllib.request.urlopen(req)
        logger.info(
            "[Email] Report %s sent to %s",
            report.alert_number,
            client_email,
        )
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Graph API error {e.code}: {e.read().decode()}")

def _build_email_html(data: dict, alert_number: str, client_name: str) -> str:
    """
    Safer compact HTML email builder.

    Uses html.escape to avoid broken HTML from AI-generated content.
    """
    title = escape(str(data.get("title") or "Security Advisory"))
    severity = escape(str(data.get("severity") or "HIGH").upper())
    cvss = escape(str(data.get("cvss_score") or "N/A"))
    description = escape(str(data.get("description") or "No description available.")).replace("\n", "<br>")
    remediation = escape(str(data.get("remediation") or "Apply vendor patches.")).replace("\n", "<br>")
    client_note = escape(str(data.get("client_note") or "Please review the advisory and take the recommended actions."))
    disclaimer = escape(str(data.get("disclaimer") or "The information is provided on an as-is basis."))
    client_name_safe = escape(str(client_name))
    alert_number_safe = escape(str(alert_number))

    refs = data.get("references") or []
    ref_html = "".join(
        f'<li><a href="{escape(str(ref))}" style="color:#1565C0;">{escape(str(ref))}</a></li>'
        for ref in refs[:8]
    )

    impacts = data.get("impact") or []
    impact_html = "".join(
        f"<li>{escape(str(item))}</li>"
        for item in impacts[:8]
    )

    products = data.get("affected_products") or data.get("target_platforms") or []
    if isinstance(products, str):
        products = [products]

    product_html = "".join(
        f"<li>{escape(str(item))}</li>"
        for item in products[:10]
    )

    return f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
</head>
<body style="margin:0;padding:0;background:#f4f6f8;font-family:Arial,Helvetica,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f8;padding:24px 0;">
    <tr>
      <td align="center">
        <table width="720" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;overflow:hidden;border:1px solid #e5e7eb;">
          <tr>
            <td style="background:#1a1a2e;padding:24px 32px;color:#ffffff;">
              <div style="font-size:11px;color:#aab;letter-spacing:2px;text-transform:uppercase;margin-bottom:8px;">
                Managed Security Advisory
              </div>
              <div style="font-size:22px;font-weight:700;line-height:1.3;">
                {title}
              </div>
              <div style="margin-top:12px;font-size:12px;color:#d1d5db;">
                Ref: {alert_number_safe} | Severity: {severity} | CVSS: {cvss}
              </div>
            </td>
          </tr>

          <tr>
            <td style="padding:20px 32px;background:#fff7ed;border-left:4px solid #ea580c;">
              <strong>Advisory for {client_name_safe}</strong><br>
              <span style="font-size:13px;color:#333;">{client_note}</span>
            </td>
          </tr>

          <tr>
            <td style="padding:24px 32px;">
              <h3 style="margin:0 0 12px;color:#111827;">Vulnerability Description</h3>
              <div style="font-size:14px;color:#333;line-height:1.7;">{description}</div>
            </td>
          </tr>

          <tr>
            <td style="padding:0 32px 24px;">
              <h3 style="margin:0 0 12px;color:#111827;">Affected Products</h3>
              <ul style="font-size:14px;color:#333;line-height:1.7;">{product_html or "<li>Refer to advisory details.</li>"}</ul>
            </td>
          </tr>

          <tr>
            <td style="padding:0 32px 24px;">
              <h3 style="margin:0 0 12px;color:#111827;">Security Impact</h3>
              <ul style="font-size:14px;color:#333;line-height:1.7;">{impact_html or "<li>Potential security impact based on vulnerability type.</li>"}</ul>
            </td>
          </tr>

          <tr>
            <td style="padding:0 32px 24px;">
              <h3 style="margin:0 0 12px;color:#111827;">Recommended Actions</h3>
              <div style="background:#e8f5e9;border-left:4px solid #2e7d32;padding:16px;font-size:14px;color:#1b5e20;line-height:1.7;">
                {remediation}
              </div>
            </td>
          </tr>

          <tr>
            <td style="padding:0 32px 24px;">
              <h3 style="margin:0 0 12px;color:#111827;">References</h3>
              <ul style="font-size:13px;line-height:1.7;">{ref_html or "<li>No references available.</li>"}</ul>
            </td>
          </tr>

          <tr>
            <td style="padding:20px 32px;background:#f9fafb;border-top:1px solid #e5e7eb;font-size:12px;color:#6b7280;line-height:1.6;">
              {disclaimer}
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
"""


# ═══════════════════════════════════════════════════════════════════════════════
# SAMPLE REPORTS
# ═══════════════════════════════════════════════════════════════════════════════

samples_router = APIRouter(prefix="/sample-reports", tags=["Sample Reports"])


@samples_router.get("")
async def get_sample_reports(
    _: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(M.SampleReport).order_by(desc(M.SampleReport.uploaded_at)))
    reports = result.scalars().all()

    return [
        {
            "doc_id": report.id,
            "filename": report.filename,
            "severity": report.severity,
            "vuln_type": report.vuln_type,
            "uploaded_at": report.uploaded_at.isoformat() if report.uploaded_at else None,
        }
        for report in reports
    ]


@samples_router.post("/upload")
async def upload_sample_report(
    file: UploadFile = File(...),
    severity: Optional[str] = None,
    vuln_type: Optional[str] = None,
    _: M.User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    Upload sample report used as RAG/style reference.
    Supports PDF, TXT, and Markdown.
    """
    filename = file.filename or "sample_report"
    ext = os.path.splitext(filename.lower())[1]

    content = await file.read()

    text = ""

    try:
        if ext == ".pdf":
            text = _extract_pdf_text(content)

        elif ext in (".txt", ".md", ".markdown"):
            text = content.decode("utf-8", errors="ignore")

        else:
            raise HTTPException(400, "Unsupported file type. Use PDF, TXT, or Markdown.")

    except HTTPException:
        raise

    except Exception as e:
        logger.error("Sample report extraction failed: %s", e, exc_info=True)
        raise HTTPException(400, f"Could not extract text from uploaded file: {e}")

    text = (text or "").strip()

    if not text:
        raise HTTPException(400, "No extractable text found in file")

    doc_id = await add_sample_report(
        text=text,
        filename=filename,
        severity=severity,
        vuln_type=vuln_type,
    )

    sample = M.SampleReport(
        filename=filename,
        severity=severity.upper() if severity else None,
        vuln_type=vuln_type,
        full_text=text,
        chroma_doc_id=doc_id,
    )

    db.add(sample)
    await db.commit()
    await db.refresh(sample)

    return {
        "ok": True,
        "doc_id": sample.id,
        "filename": filename,
        "severity": sample.severity,
        "vuln_type": sample.vuln_type,
        "chars": len(text),
    }


@samples_router.delete("/{doc_id}", status_code=204)
async def delete_sample_report_route(
    doc_id: str,
    _: M.User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    sample = await db.get(M.SampleReport, doc_id)

    if not sample:
        raise HTTPException(404, "Sample report not found")

    await db.delete(sample)
    await db.commit()


def _extract_pdf_text(content: bytes) -> str:
    import io

    text_parts = []

    try:
        import pdfplumber

        with pdfplumber.open(io.BytesIO(content)) as pdf:
            for page in pdf.pages:
                extracted = page.extract_text() or ""
                if extracted:
                    text_parts.append(extracted)

        text = "\n".join(text_parts).strip()

        if text:
            return text

    except Exception as e:
        logger.warning("pdfplumber extraction failed: %s", e)

    try:
        from PyPDF2 import PdfReader

        reader = PdfReader(io.BytesIO(content))

        for page in reader.pages:
            extracted = page.extract_text() or ""
            if extracted:
                text_parts.append(extracted)

        return "\n".join(text_parts).strip()

    except Exception as e:
        raise RuntimeError(f"PDF extraction failed: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════

system_router = APIRouter(prefix="/system", tags=["System"])


@system_router.get("/health", response_model=S.HealthOut)
async def health_check(
    _: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    db_ok = False
    redis_ok = False
    model_ok = False

    try:
        await db.execute(select(func.count(M.CVE.id)))
        db_ok = True
    except Exception as e:
        logger.warning("DB health check failed: %s", e)

    try:
        redis_client = redis.from_url(settings.REDIS_URL)
        redis_ok = bool(redis_client.ping())
    except Exception as e:
        logger.warning("Redis health check failed: %s", e)

    try:
        from services.matching.semantic_matcher import get_model

        model = get_model()
        model_ok = model is not None
    except Exception as e:
        logger.warning("Embedding model health check failed: %s", e)

    status = "ok" if db_ok and redis_ok else "degraded"

    return S.HealthOut(
        status=status,
        db=db_ok,
        redis=redis_ok,
        embedding_model_loaded=model_ok,
    )


@system_router.get("/stats", response_model=S.DashboardStats)
async def system_stats(
    _: M.User = Depends(require_reader),
    db: AsyncSession = Depends(get_db),
):
    clients = await db.scalar(select(func.count(M.Client.id))) or 0
    cves = await db.scalar(select(func.count(M.CVE.id))) or 0
    alerts_total = await db.scalar(select(func.count(M.Alert.id))) or 0
    alerts_pending = await db.scalar(
        select(func.count(M.Alert.id)).where(M.Alert.status == "pending")
    ) or 0
    reports_draft = await db.scalar(
        select(func.count(M.Report.id)).where(M.Report.status == "draft")
    ) or 0
    reports_sent = await db.scalar(
        select(func.count(M.Report.id)).where(M.Report.status == "sent")
    ) or 0
    critical_cves = await db.scalar(
        select(func.count(M.CVE.id)).where(M.CVE.severity == "CRITICAL")
    ) or 0
    kev_cves = await db.scalar(
        select(func.count(M.CVE.id)).where(M.CVE.is_kev == True)  # noqa: E712
    ) or 0

    last_poll_nvd = await _last_poll_time(db, "nvd")
    last_poll_cisa = await _last_poll_time(db, "cisa_kev")
    last_poll_rss = await _last_poll_time(db, "rss")

    return S.DashboardStats(
        clients=clients,
        cves=cves,
        alerts_pending=alerts_pending,
        alerts_total=alerts_total,
        reports_draft=reports_draft,
        reports_sent=reports_sent,
        critical_cves=critical_cves,
        kev_cves=kev_cves,
        last_poll_nvd=last_poll_nvd,
        last_poll_cisa=last_poll_cisa,
        last_poll_rss=last_poll_rss,
    )


@system_router.post("/embed-assets")
async def trigger_asset_embedding(
    _: M.User = Depends(require_admin),
):
    task = embed_assets_task.delay()

    return {
        "status": "queued",
        "task_id": task.id,
        "message": "Asset embedding task queued",
    }


async def _last_poll_time(db: AsyncSession, source: str):
    result = await db.execute(
        select(M.PollLog)
        .where(M.PollLog.source == source)
        .order_by(desc(M.PollLog.run_at))
        .limit(1)
    )

    row = result.scalar_one_or_none()

    if row:
        return row.run_at

    return None
