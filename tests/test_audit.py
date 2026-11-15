import json
import os
import stat
import threading

import pytest

from openvici.audit import GENESIS, AuditError, AuditLog


def _fill(log, n=5):
    for i in range(n):
        log.append(actor="t", action="a", target=f"x{i}", decision="allow")


def test_chain_verifies_and_file_is_private(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    assert log.head() == (-1, GENESIS)
    _fill(log)
    result = log.verify()
    assert result.ok and result.entries == 5
    assert log.head() == (4, result.head)
    assert stat.S_IMODE(os.stat(log.path).st_mode) == 0o600


def test_edited_entry_is_detected(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    _fill(log)
    lines = log.path.read_text().splitlines()
    entry = json.loads(lines[2])
    entry["decision"] = "deny"
    lines[2] = json.dumps(entry)
    log.path.write_text("\n".join(lines) + "\n")
    result = log.verify()
    assert not result.ok and "line 3" in result.error


def test_removed_middle_entry_is_detected(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    _fill(log)
    lines = log.path.read_text().splitlines()
    del lines[1]
    log.path.write_text("\n".join(lines) + "\n")
    assert not log.verify().ok


def test_truncation_needs_and_is_caught_by_checkpoint(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    _fill(log)
    checkpoint = log.head()
    lines = log.path.read_text().splitlines()
    log.path.write_text("\n".join(lines[:3]) + "\n")
    assert log.verify().ok                       # the chain alone cannot see a cut tail
    assert not log.verify(checkpoint).ok         # the saved head can


def test_full_rewrite_is_caught_by_checkpoint(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    _fill(log)
    checkpoint = log.head()
    log.path.unlink()
    _fill(AuditLog(log.path))
    assert log.verify().ok
    assert not log.verify(checkpoint).ok


def test_refuses_to_append_to_damaged_tail(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    _fill(log, 2)
    with open(log.path, "a") as fh:
        fh.write('{"seq": 2, "half')
    with pytest.raises(AuditError):
        log.append(actor="t", action="a", target="x", decision="allow")


def test_concurrent_writers_keep_one_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    threads = [threading.Thread(target=_fill, args=(AuditLog(path), 20)) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    result = AuditLog(path).verify()
    assert result.ok and result.entries == 120


def test_oversized_detail_rejected(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(AuditError):
        log.append(actor="t", action="a", target="x", decision="allow", detail={"blob": "x" * 9000})
