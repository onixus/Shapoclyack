"""Postgres PRIMARY_DB: SQLAlchemy models and Alembic migrations.

Register domain model modules before any caller uses Base.metadata, including
SQLite development schema creation, Alembic and the tenant-RLS startup check.
"""

from api.db.compliance_models import (
    ComplianceFrameworkDefinition as ComplianceFrameworkDefinition,
)
