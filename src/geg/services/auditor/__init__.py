"""Auditor: re-verify an election from public reads alone (§8.4)."""
from geg.services.auditor.auditor import AuditReport, audit

__all__ = ["audit", "AuditReport"]
