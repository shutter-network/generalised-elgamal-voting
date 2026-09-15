"""Election admin: sole config writer (register/cancel), CLI + HTTP service."""
from geg.services.admin.admin import RegistrationError, build_admin_app, cancel_election, register_election

__all__ = ["register_election", "cancel_election", "build_admin_app", "RegistrationError"]
