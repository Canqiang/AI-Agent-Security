from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "verify_reachability_closures.py"


def test_verify_reachability_closures_passes() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "UNTRUSTED_TO_ACTION never fires" in result.stdout
    assert "every path the predicate would credit is denied" in result.stdout
    assert "Both structural closures hold" in result.stdout
