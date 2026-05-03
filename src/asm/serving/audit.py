"""Structured audit log. Every prediction recorded with input hash + model version."""
import structlog

_log = structlog.get_logger("audit")


def audit_log(event: str, **fields: object) -> None:
    _log.info(event, **fields)
