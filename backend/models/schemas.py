# models/schemas.py
from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional, List, Any
from datetime import datetime


# ─── Clients ──────────────────────────────────────────────────────────────────

class AssetIn(BaseModel):
    asset_name: str = Field(..., min_length=1, max_length=512)
    cpe_string: Optional[str] = None


class ClientCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    email: str
    company: Optional[str] = None


class ClientUpdate(ClientCreate):
    pass


class AssetOut(BaseModel):
    id: str
    asset_name: str
    cpe_string: Optional[str]
    has_embedding: bool = False

    class Config:
        from_attributes = True

    @classmethod
    def from_orm_asset(cls, a) -> "AssetOut":
        return cls(
            id=a.id,
            asset_name=a.asset_name,
            cpe_string=a.cpe_string,
            has_embedding=a.embedding is not None,
        )


class ClientOut(BaseModel):
    id: str
    name: str
    email: str
    company: Optional[str]
    created_at: datetime
    assets: List[AssetOut] = []

    class Config:
        from_attributes = True


class AssetsUpdate(BaseModel):
    assets: List[AssetIn]


# ─── CVEs ─────────────────────────────────────────────────────────────────────

class CVECreate(BaseModel):
    cve_ids: str
    title: str
    vuln_type: Optional[str] = None
    severity: str = "HIGH"
    cvss_score: Optional[float] = None
    affected_products: List[str] = []
    cpe_strings: List[str] = []
    description: Optional[str] = None
    impact: List[str] = []
    attack_vector: Optional[str] = None
    remediation: Optional[str] = None
    refs: List[str] = []
    vendor_advisory: Optional[str] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v):
        if v.upper() not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            raise ValueError("severity must be CRITICAL, HIGH, MEDIUM, or LOW")
        return v.upper()


class CVEOut(BaseModel):
    id: str
    cve_ids: str
    title: str
    vuln_type: Optional[str]
    severity: str
    cvss_score: Optional[float]
    epss_score: Optional[float]
    epss_percentile: Optional[float]
    priority_score: Optional[float]
    is_kev: bool
    affected_products: Optional[List[str]]
    cpe_strings: Optional[List[str]]
    description: Optional[str]
    impact: Optional[List[str]]
    attack_vector: Optional[str]
    attack_complexity: Optional[str]
    remediation: Optional[str]
    refs: Optional[List[str]]
    patch_available: bool
    source: str
    published_at: Optional[datetime]
    date_added: datetime

    class Config:
        from_attributes = True


# ─── Alerts ───────────────────────────────────────────────────────────────────

class AlertOut(BaseModel):
    id: str
    status: str
    match_method: Optional[str]
    match_score: Optional[float]
    matched_assets: Optional[List[str]]
    matched_cpes: Optional[List[str]]
    created_at: datetime
    reviewed_at: Optional[datetime]
    reviewed_by: Optional[str]
    notes: Optional[str]
    cve: Optional[CVEOut] = None
    client: Optional[ClientOut] = None

    class Config:
        from_attributes = True


class AlertAction(BaseModel):
    status: str
    notes: Optional[str] = None
    reviewed_by: str = "analyst"

    @field_validator("status")
    @classmethod
    def validate_status(cls, v):
        if v not in ("approved", "rejected", "pending"):
            raise ValueError("status must be approved, rejected, or pending")
        return v


# ─── Reports ──────────────────────────────────────────────────────────────────

class ReportOut(BaseModel):
    id: str
    alert_id: str
    alert_number: str
    report_data: Optional[dict]
    pdf_path: Optional[str]
    pdf_filename: Optional[str]
    rag_examples_used: Optional[List[str]]
    status: str
    generated_at: datetime
    sent_at: Optional[datetime]
    cve: Optional[CVEOut] = None
    client: Optional[ClientOut] = None

    class Config:
        from_attributes = True


# ─── Stats ────────────────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    clients: int
    cves: int
    alerts_pending: int
    alerts_total: int
    reports_draft: int
    reports_sent: int
    critical_cves: int
    kev_cves: int
    last_poll_nvd: Optional[datetime]
    last_poll_cisa: Optional[datetime]
    last_poll_rss: Optional[datetime]


class PollResult(BaseModel):
    source: str
    new_cves: int
    new_alerts: int
    duration_seconds: float
    error: Optional[str] = None


class HealthOut(BaseModel):
    status: str
    db: bool
    redis: bool
    chromadb: bool
    embedding_model_loaded: bool
    version: str = "2.0.0"
