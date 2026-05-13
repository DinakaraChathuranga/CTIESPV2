# models/schemas.py
from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional, List, Any
from datetime import datetime


# ─── Auth ─────────────────────────────────────────────────────────────────────

class SetupRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=8)


class LoginRequest(BaseModel):
    username: str
    password: str

class PasswordChangeRequest(BaseModel):
    username: str
    current_password: str
    new_password: str = Field(..., min_length=8)
    confirm_password: str

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v, info):
        if "new_password" in info.data and v != info.data["new_password"]:
            raise ValueError("Passwords do not match")
        return v


class AdminPasswordResetRequest(BaseModel):
    new_password: str = Field(..., min_length=8)

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=8)
    role: str = "security_reader"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v):
        if v not in ("security_reader", "security_admin"):
            raise ValueError("role must be security_reader or security_admin")
        return v


class UserOut(BaseModel):
    id: str
    username: str
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


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
    direct_client_id: Optional[str] = None
    direct_asset_name: Optional[str] = None

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
    raw_match_score: Optional[float] = None
    boosted_match_score: Optional[float] = None
    match_decision: Optional[str] = None
    match_reason: Optional[str] = None

    ai_verdict: Optional[str] = None
    ai_confidence: Optional[float] = None
    ai_reason: Optional[str] = None
    ai_recommended_action: Optional[str] = None
    ai_verified_at: Optional[datetime] = None
    ai_verified_by: Optional[str] = None
    ai_model: Optional[str] = None
    matched_assets: Optional[List[str]]
    matched_cpes: Optional[List[str]]
    created_at: datetime
    reviewed_at: Optional[datetime]
    reviewed_by: Optional[str]
    notes: Optional[str]
    declined_at: Optional[datetime]
    restored_at: Optional[datetime]
    cve: Optional[CVEOut] = None
    client: Optional[ClientOut] = None

    class Config:
        from_attributes = True


class AlertAction(BaseModel):
    status: str
    notes: Optional[str] = None
    reviewed_by: Optional[str] = None  # overridden by auth token on server

    @field_validator("status")
    @classmethod
    def validate_status(cls, v):
        if v not in ("approved", "rejected", "pending"):
            raise ValueError("status must be approved, rejected, or pending")
        return v

class BulkApproveRequest(BaseModel):
    alert_ids: List[str]
    notes: Optional[str] = None


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
