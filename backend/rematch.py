import asyncio

async def rematch_all():
    from core.database import AsyncSessionLocal, init_db
    from models.db_models import CVE, Alert
    from services.matching.alert_factory import create_alerts_for_cve
    from sqlalchemy import select, func
    from core.config import settings
    await init_db()
    print("Threshold:", settings.SEMANTIC_MATCH_THRESHOLD)
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(CVE))
        cves = result.scalars().all()
        print("Running matcher against", len(cves), "CVEs...")
        total_alerts = 0
        for cve in cves:
            count, matches = await create_alerts_for_cve(cve, db)
            if count > 0:
                names = [m["client_name"] for m in matches]
                print("  MATCH:", cve.cve_ids, "->", count, "alerts |", names)
            total_alerts += count
        final = await db.scalar(select(func.count(Alert.id)))
        print("Total alerts created:", total_alerts)
        print("Total alerts in DB:", final)

asyncio.run(rematch_all())
