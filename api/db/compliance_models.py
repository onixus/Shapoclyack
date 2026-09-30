"""Tenant-owned, immutable compliance definitions (migration 0068, #356)."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from api.db.models import Base


class ComplianceFrameworkDefinition(Base):
    __tablename__ = "compliance_framework_definitions"

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id", ondelete="CASCADE"), primary_key=True
    )
    framework_id: Mapped[str] = mapped_column(primary_key=True)
    name: Mapped[str]
    version: Mapped[str]
    scope_note: Mapped[str]
    control_count: Mapped[int]
    definition: Mapped[dict] = mapped_column(JSON().with_variant(JSONB(), "postgresql"))
    definition_sha256: Mapped[str]
    created_at: Mapped[datetime]
    created_by: Mapped[str]
