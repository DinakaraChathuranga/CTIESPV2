# main.py
import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles

from core.config import settings
from core.database import init_db
from api.auth import auth_router
from api.routes import (
    clients_router, cves_router, alerts_router,
    reports_router, samples_router, system_router,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("cti")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("=== CTI Platform v2.0 starting ===")

    await init_db()

    try:
        from services.matching.semantic_matcher import get_model
        await asyncio.get_event_loop().run_in_executor(None, get_model)
        logger.info(f"Embedding model ready: {settings.EMBEDDING_MODEL}")
    except Exception as e:
        logger.warning(f"Embedding model load warning: {e}")

    try:
        from core.database import AsyncSessionLocal
        from models.db_models import CVE
        from sqlalchemy import select, func
        async with AsyncSessionLocal() as db:
            count = await db.scalar(select(func.count(CVE.id)))
        if count == 0:
            logger.info("Empty database — triggering initial CVE feed poll...")
            from workers.tasks import poll_nvd_task, poll_cisa_task, poll_rss_task
            poll_cisa_task.delay()
            poll_rss_task.delay()
            poll_nvd_task.delay()
    except Exception as e:
        logger.warning(f"Initial poll skipped: {e}")

    logger.info("=== CTI Platform ready ===")
    yield
    logger.info("=== CTI Platform shutting down ===")


app = FastAPI(
    title="CTI Automation Platform",
    description="Managed SOC CTI advisory automation — CVE ingestion, asset matching, AI report generation",
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.FRONTEND_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PREFIX = "/api"
app.include_router(auth_router,    prefix=PREFIX)
app.include_router(clients_router, prefix=PREFIX)
app.include_router(cves_router,    prefix=PREFIX)
app.include_router(alerts_router,  prefix=PREFIX)
app.include_router(reports_router, prefix=PREFIX)
app.include_router(samples_router, prefix=PREFIX)
app.include_router(system_router,  prefix=PREFIX)

os.makedirs(settings.REPORT_OUTPUT_DIR, exist_ok=True)
app.mount("/files/reports", StaticFiles(directory=settings.REPORT_OUTPUT_DIR), name="reports")


@app.get("/")
async def root():
    return {"name": "CTI Automation Platform", "version": "2.0.0", "docs": "/docs", "status": "running"}
