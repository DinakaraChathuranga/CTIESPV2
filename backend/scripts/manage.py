#!/usr/bin/env python3
# scripts/manage.py
"""
CTI Platform management CLI.

Usage:
  python scripts/manage.py seed-clients        # Add demo clients
  python scripts/manage.py load-samples DIR    # Bulk-index sample reports
  python scripts/manage.py embed-assets        # Re-embed all assets
  python scripts/manage.py stats               # Print system stats
  python scripts/manage.py poll SOURCE         # Trigger a feed poll
  python scripts/manage.py test-report CVE_ID  # Generate test report
"""
import asyncio
import sys
import os
import logging

# Add backend root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.chdir(os.path.dirname(os.path.dirname(__file__)))

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
logger = logging.getLogger("manage")


# ─── Seed demo clients ────────────────────────────────────────────────────────

DEMO_CLIENTS = [
    {
        "name": "Acme Corporation",
        "email": "security@acme.example.com",
        "company": "Acme Corp",
        "assets": [
            {"asset_name": "Cisco Secure Firewall Management Center", "cpe_string": "cpe:2.3:a:cisco:firepower_management_center:*"},
            {"asset_name": "Windows Server 2022",  "cpe_string": "cpe:2.3:o:microsoft:windows_server_2022:*"},
            {"asset_name": "Microsoft Exchange Server 2019", "cpe_string": "cpe:2.3:a:microsoft:exchange_server:2019:*"},
            {"asset_name": "Cisco ASA Firewall", "cpe_string": None},
            {"asset_name": "VMware vCenter Server", "cpe_string": "cpe:2.3:a:vmware:vcenter_server:*"},
        ],
    },
    {
        "name": "TechCorp Ltd",
        "email": "infosec@techcorp.example.com",
        "company": "TechCorp",
        "assets": [
            {"asset_name": "Cisco Security Cloud Control", "cpe_string": None},
            {"asset_name": "Palo Alto Networks Firewall", "cpe_string": "cpe:2.3:a:paloaltonetworks:pan-os:*"},
            {"asset_name": "VMware ESXi", "cpe_string": "cpe:2.3:o:vmware:esxi:*"},
            {"asset_name": "FortiGate Firewall", "cpe_string": "cpe:2.3:o:fortinet:fortios:*"},
        ],
    },
    {
        "name": "Global Finance Inc",
        "email": "cybersec@globalfin.example.com",
        "company": "Global Finance",
        "assets": [
            {"asset_name": "Microsoft Azure Active Directory", "cpe_string": None},
            {"asset_name": "Oracle Database 19c", "cpe_string": "cpe:2.3:a:oracle:database_server:19c:*"},
            {"asset_name": "Citrix ADC", "cpe_string": "cpe:2.3:a:citrix:application_delivery_controller:*"},
            {"asset_name": "F5 BIG-IP", "cpe_string": "cpe:2.3:a:f5:big-ip:*"},
            {"asset_name": "Splunk Enterprise", "cpe_string": "cpe:2.3:a:splunk:splunk:*"},
        ],
    },
]


async def seed_clients():
    from core.database import AsyncSessionLocal, init_db
    from models.db_models import Client, ClientAsset
    from sqlalchemy import select

    await init_db()

    async with AsyncSessionLocal() as db:
        for cdata in DEMO_CLIENTS:
            exists = (await db.execute(
                select(Client).where(Client.email == cdata["email"])
            )).scalar_one_or_none()

            if exists:
                logger.info(f"  Skip (exists): {cdata['name']}")
                continue

            client = Client(
                name=cdata["name"],
                email=cdata["email"],
                company=cdata["company"],
            )
            db.add(client)
            await db.flush()

            for a in cdata["assets"]:
                db.add(ClientAsset(
                    client_id=client.id,
                    asset_name=a["asset_name"],
                    cpe_string=a.get("cpe_string"),
                ))

            await db.commit()
            logger.info(f"  Created: {cdata['name']} ({len(cdata['assets'])} assets)")

    logger.info("Seeding done. Run 'embed-assets' to compute embeddings.")


# ─── Bulk sample report loader ────────────────────────────────────────────────

async def load_samples(directory: str):
    """
    Recursively find all PDF/TXT/MD files in a directory and index them
    into PostgreSQL (RAG store) as style examples.

    File naming convention (used to infer metadata):
      CRITICAL_RCE_cisco-fmc-2026.pdf     → severity=CRITICAL, type=RCE
      HIGH_AuthBypass_exchange.txt         → severity=HIGH,     type=AuthBypass
      advisory_20260301.pdf               → no metadata inferred
    """
    import re
    from pathlib import Path
    from core.database import AsyncSessionLocal, init_db
    from models.db_models import SampleReport
    from services.reporting.rag_store import add_sample_report
    from sqlalchemy import select

    await init_db()

    d = Path(directory)
    if not d.exists():
        logger.error(f"Directory not found: {directory}")
        return

    files = list(d.rglob("*.pdf")) + list(d.rglob("*.txt")) + list(d.rglob("*.md"))
    if not files:
        logger.error(f"No PDF/TXT/MD files found in {directory}")
        return

    logger.info(f"Found {len(files)} files in {directory}")
    indexed = 0
    skipped = 0

    for path in files:
        filename = path.name
        # Try to infer severity and type from filename
        severity = None
        vuln_type = None
        parts = filename.upper().split("_")
        if parts[0] in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            severity = parts[0]
            if len(parts) > 1:
                vuln_type = parts[1].replace("-", " ").title()

        # Read file content
        content = b""
        try:
            with open(path, "rb") as f:
                content = f.read()
        except Exception as e:
            logger.warning(f"  Cannot read {filename}: {e}")
            skipped += 1
            continue

        # Extract text
        text = ""
        if filename.lower().endswith(".pdf"):
            try:
                import pdfplumber, io
                with pdfplumber.open(io.BytesIO(content)) as pdf:
                    text = "\n\n".join((p.extract_text() or "") for p in pdf.pages)
            except Exception:
                try:
                    import PyPDF2, io
                    reader = PyPDF2.PdfReader(io.BytesIO(content))
                    text = "\n\n".join((p.extract_text() or "") for p in reader.pages)
                except Exception as e2:
                    logger.warning(f"  PDF extraction failed for {filename}: {e2}")
                    skipped += 1
                    continue
        else:
            text = content.decode("utf-8", errors="replace")

        if len(text.strip()) < 100:
            logger.warning(f"  Too little text extracted from {filename} — skipping")
            skipped += 1
            continue

        doc_id = await add_sample_report(
            text=text,
            filename=filename,
            severity=severity,
            vuln_type=vuln_type,
        )

        # Record in DB
        async with AsyncSessionLocal() as db:
            existing = (await db.execute(
                select(SampleReport).where(SampleReport.chroma_doc_id == doc_id)
            )).scalar_one_or_none()
            if not existing:
                db.add(SampleReport(
                    filename=filename,
                    severity=severity,
                    vuln_type=vuln_type,
                    full_text=text[:5000],
                    chroma_doc_id=doc_id,
                ))
                await db.commit()

        logger.info(f"  ✓ {filename} | sev={severity or '?'} type={vuln_type or '?'} | {len(text)} chars")
        indexed += 1

    logger.info(f"\nDone: {indexed} indexed, {skipped} skipped")


# ─── Embed all assets ─────────────────────────────────────────────────────────

async def embed_all():
    from core.database import AsyncSessionLocal, init_db
    from services.matching.engine import embed_all_assets
    await init_db()
    async with AsyncSessionLocal() as db:
        count = await embed_all_assets(db)
    logger.info(f"Embedded {count} assets")


# ─── Print stats ──────────────────────────────────────────────────────────────

async def stats():
    from core.database import AsyncSessionLocal, init_db
    from models.db_models import Client, CVE, Alert, Report, SampleReport, PollLog
    from sqlalchemy import select, func, desc

    await init_db()
    async with AsyncSessionLocal() as db:
        async def cnt(model, **filters):
            q = select(func.count(model.id))
            for k, v in filters.items():
                q = q.where(getattr(model, k) == v)
            return (await db.execute(q)).scalar()

        last_poll = (await db.execute(
            select(PollLog).order_by(desc(PollLog.run_at)).limit(5)
        )).scalars().all()

        print("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(" CTI Platform v2.0 — System Stats")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        print(f" Clients:         {await cnt(Client)}")
        print(f" CVEs total:      {await cnt(CVE)}")
        print(f"   CRITICAL:      {await cnt(CVE, severity='CRITICAL')}")
        print(f"   HIGH:          {await cnt(CVE, severity='HIGH')}")
        print(f"   KEV:           {(await db.execute(select(func.count(CVE.id)).where(CVE.is_kev==True))).scalar()}")
        print(f" Alerts pending:  {await cnt(Alert, status='pending')}")
        print(f" Alerts total:    {await cnt(Alert)}")
        print(f" Reports draft:   {await cnt(Report, status='draft')}")
        print(f" Reports sent:    {await cnt(Report, status='sent')}")
        print(f" Sample reports:  {await cnt(SampleReport)}")
        print("\n Recent polls:")
        for p in last_poll:
            err = f" ⚠ {p.error[:50]}" if p.error else ""
            print(f"   {p.source:<12} {str(p.run_at)[:19]}  +{p.new_cves} CVEs  +{p.new_alerts} alerts{err}")
        print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")


# ─── Test report generation ───────────────────────────────────────────────────

async def test_report(cve_id: str):
    """Generate a test report for a specific CVE ID (finds first matching alert)."""
    from core.database import AsyncSessionLocal, init_db
    from models.db_models import Alert, CVE
    from sqlalchemy import select

    await init_db()
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Alert)
            .join(CVE, Alert.cve_id == CVE.id)
            .where(CVE.cve_ids.ilike(f"%{cve_id}%"))
            .limit(1)
        )
        alert = result.scalar_one_or_none()
        if not alert:
            logger.error(f"No alert found for CVE ID: {cve_id}")
            return

        logger.info(f"Found alert {alert.id} for {alert.cve.cve_ids} → {alert.client.name}")

    from workers.tasks import generate_report_task
    result = generate_report_task(alert.id)
    logger.info(f"Report generated: {result}")


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import click

    @click.group()
    def cli():
        """CTI Platform management commands."""

    @cli.command("seed-clients")
    def seed_cmd():
        """Seed demo clients and assets into the database."""
        asyncio.run(seed_clients())

    @cli.command("load-samples")
    @click.argument("directory")
    def load_samples_cmd(directory):
        """Bulk-index sample reports from a directory into the PostgreSQL RAG store."""
        asyncio.run(load_samples(directory))

    @cli.command("embed-assets")
    def embed_cmd():
        """Compute and store embeddings for all unembedded assets."""
        asyncio.run(embed_all())

    @cli.command("stats")
    def stats_cmd():
        """Print system statistics."""
        asyncio.run(stats())

    @cli.command("poll")
    @click.argument("source", default="all")
    def poll_cmd(source):
        """Trigger a CVE feed poll. SOURCE: nvd | cisa | rss | all"""
        from workers.tasks import poll_nvd_task, poll_cisa_task, poll_rss_task
        tasks_map = {"nvd": poll_nvd_task, "cisa": poll_cisa_task, "rss": poll_rss_task}
        if source == "all":
            for t in tasks_map.values():
                t.delay()
            logger.info("Triggered: nvd, cisa, rss")
        elif source in tasks_map:
            tasks_map[source].delay()
            logger.info(f"Triggered: {source}")
        else:
            logger.error(f"Unknown source: {source}. Use: nvd | cisa | rss | all")

    @cli.command("test-report")
    @click.argument("cve_id")
    def test_report_cmd(cve_id):
        """Generate a test report for a CVE ID (finds first matching alert)."""
        asyncio.run(test_report(cve_id))

    cli()
