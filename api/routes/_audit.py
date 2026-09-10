"""The request-scoped audit context, as a route dependency (#327).

Every administrative route needs the same four facts about its caller — who,
from which address, with which client, under which ``X-Request-Id`` — and none
of them are things the service layer can see. Declaring ``audit: AuditDep``
gets them in one line, and FastAPI's per-request dependency cache means the
``get_current_user`` this shares with ``require_role``/``require_tenant`` still
runs exactly once.

The service the route calls then writes the row **in its own transaction**, so
the change and the record of it commit together — see
:mod:`api.services.audit`.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from api.auth import TokenUser, get_current_user, get_settings
from api.services import audit as audit_service
from api.settings import Settings


def audit_context(
    request: Request,
    user: Annotated[TokenUser, Depends(get_current_user)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> audit_service.AuditContext:
    return audit_service.context_from_request(request, settings, actor=user.username)


AuditDep = Annotated[audit_service.AuditContext, Depends(audit_context)]
