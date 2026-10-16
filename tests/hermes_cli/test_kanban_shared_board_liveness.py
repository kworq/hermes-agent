"""Shared board across uids: a dispatcher must not reap a worker it cannot see.

Local fix (Mike): gateways hardened with ProtectProc=invisible cannot see another
uid's processes (psutil says gone, kill(0) says EPERM) nor PID 1 (the epoch's
pid1 component comes out empty), so every foreign worker looked dead/recycled.
"""
import os

from hermes_cli import kanban_db_dispatch as d

BOOT = "e3cc25af-7158-4830-aaa2-5782e3ab0557"


def test_fingerprints_tolerate_missing_pid1_component():
    assert d._fingerprints_agree(f"{BOOT}:37|100", f"{BOOT}:|100")
    assert d._fingerprints_agree(f"{BOOT}:|100", f"{BOOT}:37|100")
    assert d._fingerprints_agree(f"{BOOT}:37|100", f"{BOOT}:37|100")


def test_fingerprints_still_detect_recycle_and_reboot():
    assert not d._fingerprints_agree(f"{BOOT}:37|101", f"{BOOT}:|100")
    assert not d._fingerprints_agree("other:37|100", f"{BOOT}:37|100")
    assert not d._fingerprints_agree(f"{BOOT}:38|100", f"{BOOT}:37|100")
    assert not d._fingerprints_agree(None, f"{BOOT}:37|100")


def test_hidden_foreign_pid_is_held_not_reaped(monkeypatch):
    monkeypatch.setattr(d._kb, "_pid_alive", lambda pid: False)

    def eperm(pid, sig):
        raise PermissionError

    monkeypatch.setattr(os, "kill", eperm)
    monkeypatch.setattr(os.path, "exists", lambda p: False)
    assert d._worker_alive(4242, f"{BOOT}:|100") is True
    # ...but its identity is unprovable, so it is never signalled by number.
    assert d._pid_recycled(4242, f"{BOOT}:|100") is True


def test_gone_pid_is_dead(monkeypatch):
    monkeypatch.setattr(d._kb, "_pid_alive", lambda pid: False)

    def esrch(pid, sig):
        raise ProcessLookupError

    monkeypatch.setattr(os, "kill", esrch)
    assert d._worker_alive(4242, f"{BOOT}:|100") is False
