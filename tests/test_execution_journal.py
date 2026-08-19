"""Unit tests for agent_common.journal.ExecutionJournal: durable state
transitions, crash-safe persistence across reloads, and pruning.
"""

from __future__ import annotations

from pathlib import Path

from agent_common.journal import ExecutionJournal


def _journal(tmp_path: Path) -> ExecutionJournal:
    return ExecutionJournal(tmp_path / "agent.journal.json")


def test_record_claimed_then_reload_from_disk_preserves_state(tmp_path):
    path = tmp_path / "agent.journal.json"
    journal = ExecutionJournal(path)
    journal.record_claimed(
        job_id="a:1",
        action_id="a",
        attempt=1,
        nonce="n",
        claim_token="c",
        idempotency_key="result-a-1",
        skill_id="service.restart",
        parameters={"service": "demo.service"},
    )
    reloaded = ExecutionJournal(path)
    assert reloaded.seen("a:1")
    assert reloaded.pending()[0].state == "claimed"
    assert reloaded.pending()[0].parameters == {"service": "demo.service"}


def test_journal_file_has_restrictive_permissions(tmp_path):
    path = tmp_path / "agent.journal.json"
    journal = ExecutionJournal(path)
    journal.record_claimed(
        job_id="a:1",
        action_id="a",
        attempt=1,
        nonce="n",
        claim_token="c",
        idempotency_key="k",
        skill_id="service.restart",
        parameters={},
    )
    assert path.stat().st_mode & 0o777 == 0o600


def test_state_transitions_progress_claimed_executing_executed_reported(tmp_path):
    journal = _journal(tmp_path)
    journal.record_claimed(
        job_id="a:1",
        action_id="a",
        attempt=1,
        nonce="n",
        claim_token="c",
        idempotency_key="k",
        skill_id="service.restart",
        parameters={},
    )
    assert journal.pending()[0].state == "claimed"

    journal.mark_executing("a:1")
    assert journal.pending()[0].state == "executing"

    result = {"success": True, "verified": True}
    journal.mark_executed("a:1", result)
    entry = journal.pending()[0]
    assert entry.state == "executed"
    assert entry.result == result

    journal.mark_reported("a:1")
    assert journal.pending() == []


def test_pending_excludes_reported_entries(tmp_path):
    journal = _journal(tmp_path)
    journal.record_claimed(
        job_id="a:1",
        action_id="a",
        attempt=1,
        nonce="n",
        claim_token="c",
        idempotency_key="k",
        skill_id="service.restart",
        parameters={},
    )
    journal.mark_reported("a:1")
    assert journal.pending() == []
    assert journal.seen("a:1")


def test_requeued_attempt_gets_a_distinct_job_id(tmp_path):
    """A requeue bumps attempt, so job_id (action_id:attempt) changes -- the
    journal must track the new attempt as a fresh entry rather than
    conflating it with the earlier, abandoned one.
    """
    journal = _journal(tmp_path)
    journal.record_claimed(
        job_id="a:1",
        action_id="a",
        attempt=1,
        nonce="n1",
        claim_token="c1",
        idempotency_key="k1",
        skill_id="service.restart",
        parameters={},
    )
    journal.mark_reported("a:1")
    journal.record_claimed(
        job_id="a:2",
        action_id="a",
        attempt=2,
        nonce="n2",
        claim_token="c2",
        idempotency_key="k2",
        skill_id="service.restart",
        parameters={},
    )
    assert journal.seen("a:1")
    assert journal.seen("a:2")
    assert journal.pending()[0].job_id == "a:2"


def test_prune_reported_keeps_only_the_most_recent_entries(tmp_path):
    journal = _journal(tmp_path)
    for i in range(5):
        job_id = f"a{i}:1"
        journal.record_claimed(
            job_id=job_id,
            action_id=f"a{i}",
            attempt=1,
            nonce="n",
            claim_token="c",
            idempotency_key="k",
            skill_id="service.restart",
            parameters={},
        )
        journal.mark_reported(job_id)
    journal.prune_reported(keep=2)
    assert len(journal._entries) == 2


def test_unknown_job_id_operations_are_safely_ignored(tmp_path):
    journal = _journal(tmp_path)
    # None of these should raise even though "missing:1" was never recorded.
    journal.mark_executing("missing:1")
    journal.mark_executed("missing:1", {"success": True})
    journal.mark_reported("missing:1")
    assert journal.pending() == []
