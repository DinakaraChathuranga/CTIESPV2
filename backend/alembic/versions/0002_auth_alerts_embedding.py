"""Add users, alert archive fields, upgrade embedding to 768-dim (all-mpnet-base-v2)

Revision ID: 0002_auth_alerts_embedding
Revises: 0001_initial
Create Date: 2026-05-01 00:00:00

Changes:
  1. Create `users` table for local auth (security_reader / security_admin)
  2. Add `declined_at` and `restored_at` columns to `alerts`
  3. Upgrade client_assets.embedding: vector(384) → vector(768)
     NOTE: Existing embeddings are dropped (incompatible dimensions).
           After deploying run: POST /api/system/embed-assets
           or click "Embed Assets" in System settings.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "0002_auth_alerts_embedding"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. Users table ────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id",              sa.String(36),  primary_key=True),
        sa.Column("username",        sa.String(255), nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role",            sa.String(50),  nullable=False, server_default="security_reader"),
        sa.Column("is_active",       sa.Boolean,     server_default="true"),
        sa.Column("created_at",      sa.DateTime,    server_default=sa.text("NOW()")),
    )
    op.create_index("ix_user_username", "users", ["username"], unique=True)

    # ── 2. Alert archive / restore timestamps ─────────────────────────────────
    op.add_column("alerts", sa.Column("declined_at", sa.DateTime, nullable=True))
    op.add_column("alerts", sa.Column("restored_at", sa.DateTime, nullable=True))

    # ── 3. Upgrade embedding vector: 384-dim → 768-dim ────────────────────────
    # Drop old HNSW index first (required before column type change)
    op.execute("DROP INDEX IF EXISTS ix_asset_embedding_hnsw")

    # Drop 384-dim column and re-add as 768-dim.
    # Old embeddings are incompatible — assets will be re-embedded after deploy.
    op.drop_column("client_assets", "embedding")
    op.execute("ALTER TABLE client_assets ADD COLUMN embedding vector(768)")

    # Recreate HNSW index for cosine similarity on 768-dim vectors
    op.execute("""
        CREATE INDEX ix_asset_embedding_hnsw
        ON client_assets
        USING hnsw (embedding vector_cosine_ops)
        WITH (m = 16, ef_construction = 64)
    """)


def downgrade() -> None:
    op.drop_index("ix_user_username", table_name="users")
    op.drop_table("users")

    op.drop_column("alerts", "declined_at")
    op.drop_column("alerts", "restored_at")

    op.execute("DROP INDEX IF EXISTS ix_asset_embedding_hnsw")
    op.drop_column("client_assets", "embedding")
    op.execute("ALTER TABLE client_assets ADD COLUMN embedding vector(384)")
    op.execute("""
        CREATE INDEX ix_asset_embedding_hnsw
        ON client_assets
        USING hnsw (embedding vector_cosine_ops)
        WITH (m = 16, ef_construction = 64)
    """)
