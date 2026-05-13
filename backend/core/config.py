# core/config.py
from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import List


class Settings(BaseSettings):
    # ── App ───────────────────────────────────────────────────────────────────
    APP_NAME: str = "CTI Platform"
    DEBUG: bool = False
    FRONTEND_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000"]

    # ── Auth / JWT ────────────────────────────────────────────────────────────
    # IMPORTANT: Set a strong random secret in production .env
    JWT_SECRET: str = "change-this-to-a-random-secret-in-production"
    JWT_EXPIRE_HOURS: int = 8

    # ── Database ──────────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql+asyncpg://cti:ctipassword@localhost:5432/ctidb"

    # ── Redis / Celery ────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

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
    # all-mpnet-base-v2: 768-dim, CPU-friendly, strong technical language understanding
    EMBEDDING_MODEL: str = "all-mpnet-base-v2"
    SEMANTIC_MATCH_THRESHOLD: float = 0.55
    CPE_MATCH_BOOST: float = 1.0

    # ── CTI Feed polling ──────────────────────────────────────────────────────
    NVD_API_KEY: str = ""
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    EPSS_API_URL: str = "https://api.first.org/data/v1/epss"
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    MIN_SEVERITY: str = "HIGH"
    INITIAL_LOOKBACK_DAYS: int = 3
    POLL_NVD_CRON: str = "0 */6 * * *"
    POLL_CISA_CRON: str = "30 */6 * * *"
    POLL_RSS_CRON: str = "*/30 * * * *"
    POLL_EPSS_CRON: str = "0 4 * * *"

    # ── RSS Feeds ─────────────────────────────────────────────────────────────
    RSS_FEEDS: List[str] = [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.bleepingcomputer.com/feed/",
        "https://www.securityweek.com/feed",
        "https://packetstormsecurity.com/headlines.xml",
        "https://www.darkreading.com/rss.xml",
        "https://feeds.feedburner.com/Securityweek",
        "https://tools.cisco.com/security/center/rss.x?cat=High",
        "https://support.microsoft.com/rss/security",
    ]

    # ── Report generation ─────────────────────────────────────────────────────
    REPORT_OUTPUT_DIR: str = "generated_reports"
    SAMPLE_REPORTS_DIR: str = "sample_reports"
    RAG_NUM_EXAMPLES: int = 3
    RAG_MIN_SIMILARITY: float = 0.4

    # ── SMTP ──────────────────────────────────────────────────────────────────
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
