"""Durable local execution journal for endpoint agents.

Trust model / why this exists
------------------------------
Before this module, an agent's only local record of job progress was a flat
set of *completed* action ids (``processed.json``), written only after a
full claim -> execute -> report cycle finished. A crash between "the
executor ran" and "the result was reported" left nothing behind: on
restart, the job was still not in ``processed``, so the agent would (once
the lease-reaper eventually requeued it) claim and *execute it again* --
for ``service.restart``, a second, unnecessary restart of a possibly
already-healthy service. That was a known, documented gap (see
``CLAUDE.md``'s Milestone 3 notes).

``ExecutionJournal`` fixes this by durably recording every state
transition -- via an atomic temp-file-then-``os.replace`` write, mirroring
the same pattern ``AgentConfig.save`` already uses, so a crash mid-write
never corrupts the file -- *before* the corresponding real-world action
happens:

1. ``record_claimed`` -- written before the job is ever handed to the
   executor. Captures everything needed to recover without re-contacting
   the control plane for job details: the skill/parameters, the claim
   token (needed to report a result), and the exact idempotency key that
   must be reused on any retry (the control plane's own idempotency-record
   table is keyed by tenant+scope+key, so reusing the same key makes a
   retried report a no-op rather than a duplicate).
2. ``mark_executing`` -- written immediately before calling the executor.
3. ``mark_executed`` -- written immediately after the executor returns,
   together with the exact result payload that will be reported.
4. ``mark_reported`` -- written only after the control plane has
   acknowledged the result.

On restart, any entry not in state ``"reported"`` describes exactly how far
the agent got, and the caller (``LinuxAgent``/``WindowsAgent``'s
``recover_interrupted_jobs``) uses that to decide what's safe to do:

- ``"executed"`` (or ``"reporting"`` -- reporting itself doesn't get a
  separate durable state since the report call is the last step and is
  itself idempotent) -- the result is already known; just resend it with
  the same idempotency key. No re-execution, ever.
- ``"claimed"`` or ``"executing"`` -- the agent does not know whether the
  underlying change happened before the crash. It must never blindly
  re-execute (that could mean a second, unwanted service restart); the
  caller is expected to *observe* current state instead (e.g. a
  verify-only check) and report accordingly.

The file itself gets the same restrictive permissions (``0o600``) as
``AgentConfig``'s credential file, since journal entries can contain
service names and other operational details about the endpoint.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

State = Literal["claimed", "executing", "executed", "reported"]


@dataclass(slots=True)
class JournalEntry:
    job_id: str
    action_id: str
    attempt: int
    nonce: str
    claim_token: str
    idempotency_key: str
    skill_id: str
    parameters: dict[str, Any]
    state: State
    result: dict[str, Any] | None = None
    updated_at: str = ""


class ExecutionJournal:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._entries: dict[str, JournalEntry] = self._load()

    def _load(self) -> dict[str, JournalEntry]:
        try:
            raw = json.loads(self.path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
        entries: dict[str, JournalEntry] = {}
        for key, value in raw.items():
            try:
                entries[key] = JournalEntry(**value)
            except TypeError:
                continue
        return entries

    def _save(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(
                {key: asdict(entry) for key, entry in self._entries.items()}, indent=2
            )
        )
        os.chmod(temporary, 0o600)
        temporary.replace(self.path)

    def seen(self, job_id: str) -> bool:
        return job_id in self._entries

    def record_claimed(
        self,
        *,
        job_id: str,
        action_id: str,
        attempt: int,
        nonce: str,
        claim_token: str,
        idempotency_key: str,
        skill_id: str,
        parameters: dict[str, Any],
    ) -> None:
        self._entries[job_id] = JournalEntry(
            job_id=job_id,
            action_id=action_id,
            attempt=attempt,
            nonce=nonce,
            claim_token=claim_token,
            idempotency_key=idempotency_key,
            skill_id=skill_id,
            parameters=parameters,
            state="claimed",
            updated_at=datetime.now(UTC).isoformat(),
        )
        self._save()

    def mark_executing(self, job_id: str) -> None:
        entry = self._entries.get(job_id)
        if entry is None:
            return
        entry.state = "executing"
        entry.updated_at = datetime.now(UTC).isoformat()
        self._save()

    def mark_executed(self, job_id: str, result: dict[str, Any]) -> None:
        entry = self._entries.get(job_id)
        if entry is None:
            return
        entry.state = "executed"
        entry.result = result
        entry.updated_at = datetime.now(UTC).isoformat()
        self._save()

    def mark_reported(self, job_id: str) -> None:
        entry = self._entries.get(job_id)
        if entry is None:
            return
        entry.state = "reported"
        entry.updated_at = datetime.now(UTC).isoformat()
        self._save()

    def pending(self) -> list[JournalEntry]:
        """Entries not yet fully reported -- what recovery needs to handle,
        oldest first.
        """
        return sorted(
            (entry for entry in self._entries.values() if entry.state != "reported"),
            key=lambda entry: entry.updated_at,
        )

    def prune_reported(self, keep: int = 500) -> None:
        reported = sorted(
            (entry for entry in self._entries.values() if entry.state == "reported"),
            key=lambda entry: entry.updated_at,
        )
        excess = len(reported) - keep
        if excess <= 0:
            return
        for entry in reported[:excess]:
            del self._entries[entry.job_id]
        self._save()
