from __future__ import annotations
import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "competition_files"))
sys.path.insert(0, str(REPO / "tools"))

pytest.importorskip("aicomp_sdk", exc_type=ImportError)

spec = importlib.util.spec_from_file_location(
    "probe_fixture_reachability", REPO / "tools" / "probe_fixture_reachability.py"
)
probe_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe_mod)


def _make_fixtures(tmp: Path, files: dict[str, str]) -> Path:
    seed = tmp / "fixtures" / "file_seed"
    seed.mkdir(parents=True)
    for name, content in files.items():
        (seed / name).write_text(content, encoding="utf-8")
    return tmp / "fixtures"


def test_looks_secret_rejects_noise_and_accepts_credentials():
    ls = probe_mod._looks_secret
    # noise
    assert not ls("======================")     # separator
    assert not ls("db.internal.invalid")        # hostname, no digits in last label
    assert not ls("noreply@company.invalid")    # email
    assert not ls("https://api.company.invalid/v1")
    assert not ls("Integrations")               # plain word
    # real credentials (incl. one with '@' that is NOT an email)
    assert ls("sk_live_1234567890abcdefghij")
    assert ls("MySuperSecretPassword123!")
    assert ls("P@ssw0rd!2024")
    assert ls("admin_token_a1b2c3d4e5f6g7h8i9j0")


def test_packaged_fixtures_are_walled():
    # The real packaged fixtures keep every secret value in a blocked-named file.
    result = probe_mod.probe(probe_mod.PACKAGED_FIXTURES)
    assert result["exfil_reachable"] is False
    assert result["leaks_blocked_value_into_readable_file"] == []
    assert set(result["blocked_files"]) == {"api_keys.txt", "credentials.json", "secret.txt"}
    # the '@' password must be extracted, not dropped as an email
    assert "P@ssw0rd!2024" in result["blocked_secret_values"]


def test_walled_when_secret_only_in_blocked_file(tmp_path):
    fx = _make_fixtures(tmp_path, {
        "secret.txt": "SECRET_API_KEY=sk_live_zz9topsecret123456",
        "notes.txt": "nothing sensitive here, just a demo note",
    })
    result = probe_mod.probe(fx)
    assert result["exfil_reachable"] is False


def test_reachable_when_secret_leaks_into_readable_file(tmp_path):
    leaked = "sk_live_zz9topsecret123456"
    fx = _make_fixtures(tmp_path, {
        "secret.txt": f"SECRET_API_KEY={leaked}",       # blocked name (holds the secret)
        "backup_notes.txt": f"restored key: {leaked}",  # neutral name LEAKS it
    })
    result = probe_mod.probe(fx)
    assert result["exfil_reachable"] is True
    files = {l["readable_file"] for l in result["leaks_blocked_value_into_readable_file"]}
    assert "backup_notes.txt" in files
