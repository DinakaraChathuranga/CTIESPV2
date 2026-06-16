import asyncio, sys
from datetime import datetime
from sqlalchemy import select
from sqlalchemy.orm import selectinload

async def main():
    from core.database import AsyncSessionLocal
    from models.db_models import Alert
    from core.config import settings
    from services.matching.verifier import verify_cve_asset_match

    def is_ms_hold(cve):
        h = " ".join([
            " ".join(cve.affected_products or []),
            " ".join(cve.cpe_strings or []),
            cve.title or "", cve.description or ""]).lower()
        return any(k in h for k in ["windows","win32","win64","win10","win11",
            "microsoft windows","windows server","microsoft office","ms office","microsoft edge"])

    async with AsyncSessionLocal() as db:
        q = await db.execute(
            select(Alert)
            .options(selectinload(Alert.cve), selectinload(Alert.client))
            .where(Alert.status=="pending", Alert.ai_verified_at.is_(None), Alert.match_score>=0.95)
            .order_by(Alert.match_score.desc())
        )
        alerts = q.scalars().all()
        print(f"Found {len(alerts)} pending alerts", flush=True)

        stats = {"v":0, "r":0, "k":0, "ms":0, "e":0}

        for i, a in enumerate(alerts, 1):
            cve, client = a.cve, a.client
            if not cve or not client:
                continue
            if is_ms_hold(cve):
                print(f"[{i}/{len(alerts)}] MS-HOLD  {cve.cve_ids} -> {client.name}", flush=True)
                stats["ms"] += 1
                continue
            asset = (a.matched_assets or ["Unknown"])[0]
            try:
                r = await verify_cve_asset_match(
                    cve_id=cve.cve_ids, title=cve.title or "", description=cve.description or "",
                    affected_products=cve.affected_products or [], cpe_strings=cve.cpe_strings or [],
                    vuln_type=cve.vuln_type or "", asset_name=asset, client_name=client.name,
                    match_method=a.match_method or "", match_score=float(a.match_score or 0))
            except Exception as e:
                print(f"[{i}/{len(alerts)}] ERR  {cve.cve_ids}: {str(e)[:100]}", flush=True)
                stats["e"] += 1
                continue
            verdict = (r.get("verdict") or "").upper()
            reason = (r.get("reason") or "")[:120]
            for f, v in {
                "ai_verdict":verdict,"ai_confidence":r.get("confidence"),
                "ai_reason":r.get("reason"),"ai_recommended_action":r.get("recommended_action"),
                "ai_verified_at":datetime.utcnow(),"ai_verified_by":"batch-verify",
                "ai_model":settings.OPENAI_MODEL}.items():
                if hasattr(a,f): setattr(a,f,v)
            if "APPROVE" not in verdict and "MATCH" not in verdict:
                a.status = "rejected"
                a.declined_at = datetime.utcnow()
                a.notes = (a.notes + "\n" if a.notes else "") + f"[Batch] Rejected: {reason}"
                stats["r"] += 1
                print(f"[{i}/{len(alerts)}] REJECT {cve.cve_ids} -> {client.name}: {reason}", flush=True)
            else:
                stats["k"] += 1
                print(f"[{i}/{len(alerts)}] KEEP   {cve.cve_ids} -> {client.name}", flush=True)
            stats["v"] += 1
            if i % 5 == 0:
                await db.commit()
        await db.commit()
        print(f"DONE  Verified:{stats[chr(34)+chr(118)+chr(34)]}", flush=True)
        print(f"  Rejected: {stats[chr(34)+chr(114)+chr(34)]}", flush=True)
        print(f"  Kept:     {stats[chr(34)+chr(107)+chr(34)]}", flush=True)
        print(f"  MS-Hold:  {stats[chr(34)+chr(109)+chr(115)+chr(34)]}", flush=True)
        print(f"  Errored:  {stats[chr(34)+chr(101)+chr(34)]}", flush=True)

asyncio.run(main())
