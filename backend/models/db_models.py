# models/db_models.py
import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    String, Text, Float, Integer, Boolean,
    DateTime, ForeignKey, JSON, UniqueConstraint, Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from pgvector.sqlalchemy import Vector
from core.database import Base


def new_uuid() -> str:
    return str(uuid.uuid4())


def now() -> datetime:
    return datetime.utcnow()


# ─── Users ────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    username: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    # 'security_reader' | 'security_admin'
    role: Mapped[str] = mapped_column(String(50), nullable=False, default="security_reader")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


# ─── Clients ──────────────────────────────────────────────────────────────────

class Client(Base):
    __tablename__ = "clients"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    email_cc: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, default="")
    company: Mapped[Optional[str]] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)

    assets: Mapped[List["ClientAsset"]] = relationship(
        "ClientAsset", back_populates="client",
        cascade="all, delete-orphan", lazy="selectin"
    )
    alerts: Mapped[List["Alert"]] = relationship("Alert", back_populates="client")


class ClientAsset(Base):
    __tablename__ = "client_assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id", ondelete="CASCADE"))
    asset_name: Mapped[str] = mapped_column(String(512), nullable=False)
    cpe_string: Mapped[Optional[str]] = mapped_column(Text)
    # 768-dim all-mpnet-base-v2 embeddings
    embedding: Mapped[Optional[List[float]]] = mapped_column(Vector(768))

    client: Mapped["Client"] = relationship("Client", back_populates="assets")

    __table_args__ = (
        Index("ix_asset_client", "client_id"),
        Index(
            "ix_asset_embedding_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_with={"m": 16, "ef_construction": 64},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )


# ─── CVEs ─────────────────────────────────────────────────────────────────────

class CVE(Base):
    __tablename__ = "cves"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    cve_ids: Mapped[str] = mapped_column(String(512), nullable=False, unique=True, index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    vuln_type: Mapped[Optional[str]] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM", index=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(255))
    epss_score: Mapped[Optional[float]] = mapped_column(Float)
    epss_percentile: Mapped[Optional[float]] = mapped_column(Float)
    priority_score: Mapped[Optional[float]] = mapped_column(Float)
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False)
    affected_products: Mapped[Optional[dict]] = mapped_column(JSON)
    cpe_strings: Mapped[Optional[dict]] = mapped_column(JSON)
    description: Mapped[Optional[str]] = mapped_column(Text)
    impact: Mapped[Optional[dict]] = mapped_column(JSON)
    attack_vector: Mapped[Optional[str]] = mapped_column(String(512))
    attack_complexity: Mapped[Optional[str]] = mapped_column(String(50))
    privileges_required: Mapped[Optional[str]] = mapped_column(String(50))
    remediation: Mapped[Optional[str]] = mapped_column(Text)
    refs: Mapped[Optional[dict]] = mapped_column(JSON)
    vendor_advisory: Mapped[Optional[str]] = mapped_column(Text)
    patch_available: Mapped[bool] = mapped_column(Boolean, default=False)
    source: Mapped[str] = mapped_column(String(50), default="manual")
    raw_data: Mapped[Optional[dict]] = mapped_column(JSON)
    published_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    date_added: Mapped[datetime] = mapped_column(DateTime, default=now, index=True)

    alerts: Mapped[List["Alert"]] = relationship("Alert", back_populates="cve")

    __table_args__ = (
        Index("ix_cve_severity_date", "severity", "date_added"),
        Index("ix_cve_priority", "priority_score"),
    )


# ─── Alerts ───────────────────────────────────────────────────────────────────

class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    cve_id: Mapped[str] = mapped_column(String(36), ForeignKey("cves.id", ondelete="CASCADE"), index=True)
    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)

    # Match metadata
    match_method: Mapped[Optional[str]] = mapped_column(String(50))
    match_score: Mapped[Optional[float]] = mapped_column(Float)
    raw_match_score: Mapped[Optional[float]] = mapped_column(Float)
    boosted_match_score: Mapped[Optional[float]] = mapped_column(Float)
    match_decision: Mapped[Optional[str]] = mapped_column(String(50))
    match_reason: Mapped[Optional[str]] = mapped_column(Text)

    matched_assets: Mapped[Optional[dict]] = mapped_column(JSON)
    matched_cpes: Mapped[Optional[dict]] = mapped_column(JSON)

    # AI verification metadata
    ai_verdict: Mapped[Optional[str]] = mapped_column(String(30))
    ai_confidence: Mapped[Optional[float]] = mapped_column(Float)
    ai_reason: Mapped[Optional[str]] = mapped_column(Text)
    ai_recommended_action: Mapped[Optional[str]] = mapped_column(Text)
    ai_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    ai_verified_by: Mapped[Optional[str]] = mapped_column(String(255))
    ai_model: Mapped[Optional[str]] = mapped_column(String(100))

    # Workflow
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now, index=True)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    reviewed_by: Mapped[Optional[str]] = mapped_column(String(255))
    notes: Mapped[Optional[str]] = mapped_column(Text)

    # Archive / restore tracking
    declined_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    restored_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    cve: Mapped["CVE"] = relationship("CVE", back_populates="alerts", lazy="selectin")
    client: Mapped["Client"] = relationship("Client", back_populates="alerts", lazy="selectin")
    report: Mapped[Optional["Report"]] = relationship("Report", back_populates="alert", uselist=False)

    __table_args__ = (
        UniqueConstraint("cve_id", "client_id", name="uq_alert_cve_client"),
        Index("ix_alert_status_created", "status", "created_at"),
    )
# ─── Reports ──────────────────────────────────────────────────────────────────

class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    alert_id: Mapped[str] = mapped_column(String(36), ForeignKey("alerts.id", ondelete="CASCADE"), unique=True)
    cve_id: Mapped[str] = mapped_column(String(36), ForeignKey("cves.id", ondelete="CASCADE"))
    client_id: Mapped[str] = mapped_column(String(36), ForeignKey("clients.id", ondelete="CASCADE"))
    alert_number: Mapped[str] = mapped_column(String(50))
    report_data: Mapped[Optional[dict]] = mapped_column(JSON)
    pdf_path: Mapped[Optional[str]] = mapped_column(Text)
    pdf_filename: Mapped[Optional[str]] = mapped_column(String(255))
    rag_examples_used: Mapped[Optional[dict]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(20), default="draft")
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    alert: Mapped["Alert"] = relationship("Alert", back_populates="report")
    cve: Mapped["CVE"] = relationship("CVE", lazy="selectin")
    client: Mapped["Client"] = relationship("Client", lazy="selectin")


# ─── Poll logs ────────────────────────────────────────────────────────────────

class PollLog(Base):
    __tablename__ = "poll_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    source: Mapped[str] = mapped_column(String(100), index=True)
    run_at: Mapped[datetime] = mapped_column(DateTime, default=now, index=True)
    new_cves: Mapped[int] = mapped_column(Integer, default=0)
    new_alerts: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[Optional[float]] = mapped_column(Float)
    error: Mapped[Optional[str]] = mapped_column(Text)
    metadata_: Mapped[Optional[dict]] = mapped_column("metadata", JSON)


# ─── Sample Reports (for RAG) ─────────────────────────────────────────────────

class SampleReport(Base):
    __tablename__ = "sample_reports"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    filename: Mapped[str] = mapped_column(String(255))
    severity: Mapped[Optional[str]] = mapped_column(String(20))
    vuln_type: Mapped[Optional[str]] = mapped_column(String(255))
    full_text: Mapped[Optional[str]] = mapped_column(Text)
    chroma_doc_id: Mapped[Optional[str]] = mapped_column(String(255))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=now)

class NotificationRecipient(Base):
    __tablename__ = "notification_recipients"

    id:                Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email:             Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    name:              Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    notify_openai:     Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notify_feeds:      Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notify_pipeline:   Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    notify_email_send: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    enabled:           Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at:        Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)

