import asyncio

async def dry_run():
    from core.database import AsyncSessionLocal, init_db
    from models.db_models import CVE
    from services.matching.engine import match_cve_to_clients
    from sqlalchemy import select
    
    await init_db()
    async with AsyncSessionLocal() as db:
        # Grab the 100 most recent HIGH/CRITICAL CVEs to test against your rules
        print("Fetching recent CVEs for dry-run testing...")
        result = await db.execute(
            select(CVE)
            .where(CVE.severity.in_(["CRITICAL", "HIGH"]))
            .order_by(CVE.date_added.desc())
            .limit(100)
        )
        cves = result.scalars().all()
        
        matches_found = 0
        for cve in cves:
            # match_cve_to_clients ONLY calculates vectors in memory. It writes nothing to the DB.
            matches = await match_cve_to_clients(cve, db)
            if matches:
                matches_found += len(matches)
                print(f"\n🚨 {cve.cve_ids} | Products: {cve.affected_products}")
                for m in matches:
                    print(f"   -> Client: {m.client_name} | Asset: {m.matched_assets} | Score: {m.score} ({m.method})")
        
        print(f"\n✅ Dry run complete. Found {matches_found} potential matches.")
        print("🛡️  NO alerts were created in the database. NO API calls were made.")

if __name__ == "__main__":
    asyncio.run(dry_run())
