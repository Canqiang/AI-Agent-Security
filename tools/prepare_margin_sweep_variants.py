"""Build Kaggle submission variants that sweep (BUDGET_MARGIN, HARD_N_CAP) over
the proven adaptive per-model fill in `src/attack.py`.

2026-07-04 context: three static-N submissions (900/1150/670) all failed
"incorrect format" against a real wall that turned out to be time-varying
shared-resource contention (leaderboard timestamps show other teams landing
70-100+ the same day, both before and after our failures) rather than a fixed
ceiling -- see memory scoring-gateway-and-adaptive-n / competitive-landscape.
`src/attack.py` reverted to the one config PROVEN not to fail (ref 54283427,
margin=0.55/cap=1100, public 32.415). This script generates sibling rungs that
vary only the two safety knobs -- everything else (TEMPLATE, PAYLOAD, probe,
cold-start fix) stays byte-identical to `src/attack.py` -- so today's fresh
5-submission quota maps out where today's real ceiling sits instead of
guessing a single static N again.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
BASE_NOTEBOOK = REPO / "notebooks" / "submission.ipynb"
BASE_SOURCE = REPO / "src" / "attack.py"
DEFAULT_OUT_ROOT = REPO / "kaggle_push" / "submission_variants"
KERNEL_ID = "canqiang/aiagsec-submission"
KERNEL_TITLE = "AIAgSec Submission"

_MARGIN_RE = re.compile(r"^BUDGET_MARGIN = [0-9.]+(\s*#.*)?$", re.MULTILINE)
_CAP_RE = re.compile(r"^HARD_N_CAP = \d+(\s*#.*)?$", re.MULTILINE)


@dataclass(frozen=True)
class Rung:
    name: str
    budget_margin: float
    hard_n_cap: int
    description: str


RUNGS: dict[str, Rung] = {
    "canary_m030_cap600": Rung(
        name="canary_m030_cap600",
        budget_margin=0.30,
        hard_n_cap=600,
        description="conservative canary: confirms SECRET_MARKER still scores + today's contention, high land-confidence",
    ),
    "step_m070_cap1400": Rung(
        name="step_m070_cap1400",
        budget_margin=0.70,
        hard_n_cap=1400,
        description="moderate step above the proven 07-03 config (margin 0.55/cap 1100)",
    ),
    "step_m085_cap1700": Rung(
        name="step_m085_cap1700",
        budget_margin=0.85,
        hard_n_cap=1700,
        description="aggressive step, probing toward the Victor-Merckle-scale ceiling",
    ),
    "moonshot_m095_cap1950": Rung(
        name="moonshot_m095_cap1950",
        budget_margin=0.95,
        hard_n_cap=1950,
        description="moonshot: near-max margin, cap near the SDK's 2000-candidate ceiling",
    ),
}


def load_notebook(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("cells"), list):
        raise ValueError(f"{path} is not a notebook JSON object")
    return data


def kernel_metadata() -> dict[str, Any]:
    return {
        "id": KERNEL_ID,
        "title": KERNEL_TITLE,
        "code_file": "submission.ipynb",
        "language": "python",
        "kernel_type": "notebook",
        "is_private": True,
        "enable_gpu": True,
        "enable_tpu": False,
        "enable_internet": False,
        "machine_shape": "NvidiaTeslaT4",
        "dataset_sources": [],
        "competition_sources": ["ai-agent-security-multi-step-tool-attacks"],
        "kernel_sources": [],
    }


def rung_attack_code(rung: Rung, base_source: str) -> str:
    text, n_margin = _MARGIN_RE.subn(
        f"BUDGET_MARGIN = {rung.budget_margin}          # 07-04 margin-sweep rung: {rung.name}",
        base_source,
    )
    if n_margin != 1:
        raise ValueError(f"expected exactly one BUDGET_MARGIN assignment, found {n_margin}")
    text, n_cap = _CAP_RE.subn(
        f"HARD_N_CAP = {rung.hard_n_cap}             # 07-04 margin-sweep rung: {rung.name}",
        text,
    )
    if n_cap != 1:
        raise ValueError(f"expected exactly one HARD_N_CAP assignment, found {n_cap}")
    return text


def write_variant(rung: Rung, out_root: Path) -> dict[str, Any]:
    base_source = BASE_SOURCE.read_text(encoding="utf-8")
    code = rung_attack_code(rung, base_source)

    notebook = load_notebook(BASE_NOTEBOOK)
    code_cell = notebook["cells"][2]
    if code_cell.get("cell_type") != "code":
        raise ValueError("expected submission attack cell at index 2")
    source = "%%writefile /kaggle/working/attack.py\n" + code
    code_cell["source"] = [line + "\n" for line in source.splitlines()]
    code_cell["outputs"] = []
    code_cell["execution_count"] = None

    out_dir = out_root / rung.name
    out_dir.mkdir(parents=True, exist_ok=True)
    notebook_path = out_dir / "submission.ipynb"
    metadata_path = out_dir / "kernel-metadata.json"
    manifest_path = out_dir / "variant-manifest.json"
    source_path = out_dir / "attack.py"
    notebook_path.write_text(json.dumps(notebook, indent=1) + "\n", encoding="utf-8")
    metadata_path.write_text(
        json.dumps(kernel_metadata(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    source_path.write_text(code, encoding="utf-8")

    manifest = {
        "name": rung.name,
        "chain_k": 1,
        "mode": "adaptive_margin_sweep",
        "n_candidates": rung.hard_n_cap,
        "budget_margin": rung.budget_margin,
        "hard_n_cap": rung.hard_n_cap,
        "expected_public_score": round(rung.hard_n_cap * 0.09, 3),
        "description": rung.description,
        "folder": str(out_dir),
        "notebook": str(notebook_path),
        "metadata": str(metadata_path),
        "source": str(source_path),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def parse_rungs(value: str) -> list[Rung]:
    names = [item.strip() for item in value.split(",") if item.strip()]
    unknown = sorted(set(names) - set(RUNGS))
    if unknown:
        raise ValueError(f"unknown rung(s): {', '.join(unknown)}")
    return [RUNGS[name] for name in names]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rungs", default=",".join(RUNGS), help="comma-separated rung names")
    parser.add_argument("--out-root", type=Path, default=DEFAULT_OUT_ROOT)
    args = parser.parse_args()

    manifests = [write_variant(rung, args.out_root) for rung in parse_rungs(args.rungs)]
    print(json.dumps({"ok": True, "variants": manifests}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
