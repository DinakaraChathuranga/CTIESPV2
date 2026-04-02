"""Initial schema — all tables with pgvector

Revision ID: 0001_initial
Revises:
Create Date: 2026-01-01 00:00:00
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from pgvector.sqlalchemy import Vector

revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Enable extensions
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    op.create_table(
        "clients",
        sa.Column("id",         sa.String(36),  primary_key=True),
        sa.Column("name",       sa.String(255), nullable=False),
        sa.Column("email",      sa.String(255), nullable=False),
        sa.Column("company",    sa.String(255)),
        sa.Column("created_at", sa.DateTime,    server_default=sa.text("NOW()")),
        sa.Column("updated_at", sa.DateTime,    server_default=sa.text("NOW()")),
    )

    op.create_table(
        "client_assets",
        sa.Column("id",          sa.String(36),  primary_key=True),
        sa.Column("client_id",   sa.String(36),  sa.ForeignKey("clients.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_name",  sa.String(512), nullable=False),
        sa.Column("cpe_string",  sa.Text),
        sa.Column("embedding",   Vector(384)),
    )
    op.create_index("ix_asset_client", "client_assets", ["client_id"])
    # hnsw vector index — works on empty tables, better for cosine similarity
    op.execute("""
        CREATE INDEX ix_asset_embedding_hnsw
        ON client_assets
        USING hnsw (embedding vector_cosine_ops)
        WITH (m = 16, ef_construction = 64)
    """)

    op.create_table(
        "cves",
        sa.Column("id",                sa.String(36),  primary_key=True),
        sa.Column("cve_ids",           sa.String(512), nullable=False, unique=True),
        sa.Column("title",             sa.Text,        nullable=False),
        sa.Column("vuln_type",         sa.String(512)),
        sa.Column("severity",          sa.String(20),  server_default="MEDIUM"),
        sa.Column("cvss_score",        sa.Float),
        sa.Column("cvss_vector",       sa.String(255)),
        sa.Column("epss_score",        sa.Float),
        sa.Column("epss_percentile",   sa.Float),
        sa.Column("priority_score",    sa.Float),
        sa.Column("is_kev",            sa.Boolean,     server_default="false"),
        sa.Column("affected_products", sa.JSON),
        sa.Column("cpe_strings",       sa.JSON),
        sa.Column("description",       sa.Text),
        sa.Column("impact",            sa.JSON),
        sa.Column("attack_vector",     sa.String(512)),
        sa.Column("attack_complexity", sa.String(50)),
        sa.Column("privileges_required", sa.String(50)),
        sa.Column("remediation",       sa.Text),
        sa.Column("refs",              sa.JSON),
        sa.Column("vendor_advisory",   sa.Text),
        sa.Column("patch_available",   sa.Boolean,     server_default="false"),
        sa.Column("source",            sa.String(50),  server_default="manual"),
        sa.Column("raw_data",          sa.JSON),
        sa.Column("published_at",      sa.DateTime),
        sa.Column("date_added",        sa.DateTime,    server_default=sa.text("NOW()")),
    )
    op.create_index("ix_cve_cve_ids",   "cves", ["cve_ids"])
    op.create_index("ix_cve_severity",  "cves", ["severity"])
    op.create_index("ix_cve_date",      "cves", ["date_added"])
    op.create_index("ix_cve_priority",  "cves", ["priority_score"])

    op.create_table(
        "alerts",
        sa.Column("id",              sa.String(36), primary_key=True),
        sa.Column("cve_id",          sa.String(36), sa.ForeignKey("cves.id",    ondelete="CASCADE"), nullable=False),
        sa.Column("client_id",       sa.String(36), sa.ForeignKey("clients.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status",          sa.String(20), server_default="pending"),
        sa.Column("match_method",    sa.String(50)),
        sa.Column("match_score",     sa.Float),
        sa.Column("matched_assets",  sa.JSON),
        sa.Column("matched_cpes",    sa.JSON),
        sa.Column("created_at",      sa.DateTime,   server_default=sa.text("NOW()")),
        sa.Column("reviewed_at",     sa.DateTime),
        sa.Column("reviewed_by",     sa.String(255)),
        sa.Column("notes",           sa.Text),
        sa.UniqueConstraint("cve_id", "client_id", name="uq_alert_cve_client"),
    )
    op.create_index("ix_alert_cve_id",    "alerts", ["cve_id"])
    op.create_index("ix_alert_client_id", "alerts", ["client_id"])
    op.create_index("ix_alert_status",    "alerts", ["status"])

    op.create_table(
        "reports",
        sa.Column("id",                sa.String(36), primary_key=True),
        sa.Column("alert_id",          sa.String(36), sa.ForeignKey("alerts.id",  ondelete="CASCADE"), unique=True),
        sa.Column("cve_id",            sa.String(36), sa.ForeignKey("cves.id",    ondelete="CASCADE")),
        sa.Column("client_id",         sa.String(36), sa.ForeignKey("clients.id", ondelete="CASCADE")),
        sa.Column("alert_number",      sa.String(50)),
        sa.Column("report_data",       sa.JSON),
        sa.Column("pdf_path",          sa.Text),
        sa.Column("pdf_filename",      sa.String(255)),
        sa.Column("rag_examples_used", sa.JSON),
        sa.Column("status",            sa.String(20), server_default="draft"),
        sa.Column("generated_at",      sa.DateTime,   server_default=sa.text("NOW()")),
        sa.Column("sent_at",           sa.DateTime),
    )

    op.create_table(
        "poll_logs",
        sa.Column("id",               sa.String(36), primary_key=True),
        sa.Column("source",           sa.String(100), nullable=False),
        sa.Column("run_at",           sa.DateTime,    server_default=sa.text("NOW()")),
        sa.Column("new_cves",         sa.Integer,     server_default="0"),
        sa.Column("new_alerts",       sa.Integer,     server_default="0"),
        sa.Column("duration_seconds", sa.Float),
        sa.Column("error",            sa.Text),
        sa.Column("metadata",         sa.JSON),
    )
    op.create_index("ix_poll_source", "poll_logs", ["source"])
    op.create_index("ix_poll_run_at", "poll_logs", ["run_at"])

    op.create_table(
        "sample_reports",
        sa.Column("id",            sa.String(36), primary_key=True),
        sa.Column("filename",      sa.String(255), nullable=False),
        sa.Column("severity",      sa.String(20)),
        sa.Column("vuln_type",     sa.String(255)),
        sa.Column("full_text",     sa.Text),
        sa.Column("chroma_doc_id", sa.String(255)),
        sa.Column("uploaded_at",   sa.DateTime, server_default=sa.text("NOW()")),
    )


def downgrade() -> None:
    for tbl in ("sample_reports", "poll_logs", "reports", "alerts", "cves", "client_assets", "clients"):
        op.drop_table(tbl)
