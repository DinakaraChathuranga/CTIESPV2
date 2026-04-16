# core/config.py
from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import List


class Settings(BaseSettings):
    # ── App ───────────────────────────────────────────────────────────────────
    APP_NAME: str = "CTI Platform"
    DEBUG: bool = False
    FRONTEND_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://cti:ctipassword@localhost:5432/ctidb"

    # ── Redis / Celery ────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── ChromaDB ──────────────────────────────────────────────────────────────
    #CHROMA_HOST: str = "localhost"
    #CHROMA_PORT: int = 8001
    #CHROMA_COLLECTION_REPORTS: str = "sample_reports"
    #CHROMA_COLLECTION_ASSETS: str = "client_assets"

    # ── LLM ───────────────────────────────────────────────────────────────────
    ANTHROPIC_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    GOOGLE_CLOUD_PROJECT: str = ""
    GOOGLE_CLOUD_LOCATION: str = "us-central1"
    GOOGLE_APPLICATION_CREDENTIALS: str = ""
    VERTEX_MODEL: str = "gemini-2.0-flash"
    CLAUDE_MODEL: str = "claude-sonnet-4-5"
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o"
    MAX_REPORT_TOKENS: int = 4096

    # ── Embedding model ───────────────────────────────────────────────────────
    EMBEDDING_MODEL: str = "all-MiniLM-L6-v2"
    SEMANTIC_MATCH_THRESHOLD: float = 0.55   # cosine similarity min (0–1)
    CPE_MATCH_BOOST: float = 1.0             # CPE exact match gets priority

    # ── CTI Feed polling ──────────────────────────────────────────────────────
    NVD_API_KEY: str = ""
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API_URL: str = "https://api.first.org/data/v1/epss"
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # Severity threshold for auto-ingest (CRITICAL / HIGH / MEDIUM / LOW)
    MIN_SEVERITY: str = "HIGH"
    # Days back to fetch on first run
    INITIAL_LOOKBACK_DAYS: int = 3
    # Polling schedules (cron strings for Celery beat)
    POLL_NVD_CRON: str = "0 */6 * * *"       # every 6h
    POLL_CISA_CRON: str = "30 */6 * * *"     # every 6h offset
    POLL_RSS_CRON: str = "*/30 * * * *"      # every 30 min
    POLL_EPSS_CRON: str = "0 4 * * *"        # daily at 04:00

    # ── RSS Feeds ─────────────────────────────────────────────────────────────
    RSS_FEEDS: List[str] = [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.bleepingcomputer.com/feed/",
        "https://www.securityweek.com/feed",
        "https://packetstormsecurity.com/headlines.xml",
        "https://www.darkreading.com/rss.xml",
        "https://feeds.feedburner.com/Securityweek",
        # Vendor security advisories
        "https://tools.cisco.com/security/center/rss.x?cat=High",
        "https://support.microsoft.com/rss/security",
    ]

    # ── Report generation ─────────────────────────────────────────────────────
    REPORT_OUTPUT_DIR: str = "generated_reports"
    SAMPLE_REPORTS_DIR: str = "sample_reports"
    RAG_NUM_EXAMPLES: int = 3        # How many similar reports to inject as style examples
    RAG_MIN_SIMILARITY: float = 0.4  # Minimum similarity to use as RAG example

    # ── SMTP (Phase 2 — keep existing) ───────────────────────────────────────
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASS: str = ""
    EMAIL_FROM: str = "CTI Security Team <cti@yoursoc.com>"

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()

settings = get_settings()

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
