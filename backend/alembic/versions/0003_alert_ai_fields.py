"""Add AI verification and extended match fields to alerts

Revision ID: 0003_alert_ai_fields
Revises: 0002_auth_alerts_embedding
Create Date: 2026-05-13 00:00:00
"""
from typing import Sequence, Union
from alembic import op

revision: str = "0003_alert_ai_fields"
down_revision: Union[str, None] = "0002_auth_alerts_embedding"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Use IF NOT EXISTS so this is safe to run even if columns already exist
    statements = [
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS raw_match_score FLOAT",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS boosted_match_score FLOAT",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS match_decision VARCHAR(50)",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS match_reason TEXT",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_verdict VARCHAR(30)",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_confidence FLOAT",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_reason TEXT",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_recommended_action TEXT",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_verified_at TIMESTAMP",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_verified_by VARCHAR(255)",
        "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_model VARCHAR(100)",
    ]
    for sql in statements:
        op.execute(sql)


def downgrade() -> None:
    cols = [
        "raw_match_score", "boosted_match_score", "match_decision", "match_reason",
        "ai_verdict", "ai_confidence", "ai_reason", "ai_recommended_action",
        "ai_verified_at", "ai_verified_by", "ai_model",
    ]
    for col in cols:
        op.execute(f"ALTER TABLE alerts DROP COLUMN IF EXISTS {col}")
