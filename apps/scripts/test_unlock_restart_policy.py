#!/usr/bin/env python3
"""Host regression tests for UnlockRestartPolicy and BibaVpnService unlock restart wiring."""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVICE = (
    ROOT
    / "apps/bibavpn-desktop/src-tauri/android-bibavpn-extras/java/dev/bibavpn/BibaVpnService.kt"
)
POLICY = (
    ROOT
    / "apps/bibavpn-desktop/src-tauri/android-bibavpn-extras/java/dev/bibavpn/UnlockRestartPolicy.kt"
)
INTEGRATE = ROOT / "apps/scripts/integrate-bibavpn-into-tauri-android.sh"
DRIVER = ROOT / "apps/scripts/unlock_restart_policy_driver.kt"


def test_no_string_intent_action_mismatch() -> None:
    text = SERVICE.read_text(encoding="utf-8")
    assert 'maybeRestartStackAfterUnlockEvent("SCREEN_ON")' not in text, (
        "receiver must not pass short SCREEN_ON string"
    )
    assert 'maybeRestartStackAfterUnlockEvent("USER_PRESENT")' not in text, (
        "receiver must not pass short USER_PRESENT string"
    )
    assert "UnlockRestartEvent.SCREEN_ON" in text
    assert "UnlockRestartEvent.USER_PRESENT" in text
    assert "UnlockRestartPolicy.decide" in text
    # Audited bug: short source compared to Intent.ACTION_SCREEN_ON while caller passed "SCREEN_ON"
    assert not re.search(
        r'source\s*==\s*Intent\.ACTION_SCREEN_ON',
        text,
    ), "bounce guard must not compare against Intent.ACTION_SCREEN_ON in the service"


def test_integrate_copies_policy() -> None:
    text = INTEGRATE.read_text(encoding="utf-8")
    assert "UnlockRestartPolicy.kt" in text


def test_stop_requested_gates_queued_rerun() -> None:
    text = SERVICE.read_text(encoding="utf-8")
    assert "stopRequested" in text
    finally_block = text.split("finally {", 1)[1].split("}", 1)[0]
    perform = text.split("private fun performFullStackRestart", 1)[1]
    perform_finally = perform.split("finally {", 1)[1].split("\n            },", 1)[0]
    assert "stopRequested" in perform_finally
    assert re.search(r"if\s*\(\s*rerun\s*&&\s*!stopRequested\s*\)", perform_finally), (
        "queued follow-up must be gated on stopRequested"
    )


def run_policy_table_with_kotlinc() -> None:
    kotlinc = shutil.which("kotlinc")
    if kotlinc is None:
        print("kotlinc not found — policy table execution skipped")
        return
    work = ROOT / "target/unlock-restart-policy-test"
    work.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            kotlinc,
            str(POLICY),
            str(DRIVER),
            "-d",
            str(work),
        ],
        check=True,
        cwd=ROOT,
    )
    subprocess.run(
        ["kotlin", "-classpath", str(work), "Unlock_restart_policy_driverKt"],
        check=True,
        cwd=ROOT,
    )


def main() -> None:
    test_no_string_intent_action_mismatch()
    test_integrate_copies_policy()
    test_stop_requested_gates_queued_rerun()
    run_policy_table_with_kotlinc()
    print("ok")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as e:
        print(f"FAIL: {e}", file=sys.stderr)
        sys.exit(1)
