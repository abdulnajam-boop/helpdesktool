"""Structured JSON logging with per-request correlation ids.

Every log line emitted through the standard ``logging`` module (after
``configure_logging()`` runs, which every entry point — `api.py`'s
`uvicorn` process, `webhook_worker.py`, `lease_reaper.py`, `seed.py` — calls
at startup) is a single-line JSON object: ``timestamp``, ``level``,
``logger``, ``message``, and, inside an HTTP request, ``request_id`` — the
same id ``RequestIdMiddleware`` (in ``api.py``) generates or propagates from
an incoming ``X-Request-ID`` header and echoes back in the response. This is
what lets an operator (or a log aggregator) pull every line touched by one
HTTP request, and correlate it with the domain-level ``correlation_id``
already threaded through the audit hash-chain (`audit.py`) and Prometheus
request labels (`metrics.py`) — the two ids answer different questions
("what happened during this HTTP call" vs. "what happened to this
action/incident/ticket over its lifetime") and are deliberately not merged
into one.

Never log secrets or full request/response bodies here — this module only
ever receives whatever the calling code explicitly passes to a `logging`
call; existing redaction (`helpdesktool.events.sanitize_event_data`) is
unaffected and unrelated to this module.
"""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any

_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)


def set_request_id(value: str | None) -> None:
    _request_id.set(value)


def get_request_id() -> str | None:
    return _request_id.get()


_RESERVED_LOG_RECORD_ATTRS = frozenset(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__
)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = get_request_id()
        if request_id is not None:
            payload["request_id"] = request_id
        for key, value in record.__dict__.items():
            if key not in _RESERVED_LOG_RECORD_ATTRS and key not in payload:
                payload[key] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
