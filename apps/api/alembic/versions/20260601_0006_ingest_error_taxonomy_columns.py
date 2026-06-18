"""Add ingest job error taxonomy columns.

Revision ID: 20260601_0006
Revises: 20260601_0005
Create Date: 2026-06-01
"""

from alembic import op


revision = "20260601_0006"
down_revision = "20260601_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Idempotent: the baseline migration's create_all already builds the current
    # ingest_jobs model (which includes these columns) on fresh databases.
    op.execute("ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS error_code VARCHAR(64)")
    op.execute("ALTER TABLE ingest_jobs ADD COLUMN IF NOT EXISTS error_stage VARCHAR(64)")


def downgrade() -> None:
    op.execute("ALTER TABLE ingest_jobs DROP COLUMN IF EXISTS error_stage")
    op.execute("ALTER TABLE ingest_jobs DROP COLUMN IF EXISTS error_code")
