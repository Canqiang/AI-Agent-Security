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
    # 2026-07-05 BARE-template sweep. Margins chosen to reuse the verbose sweep's
    # datapoints (0.55->30.57, 0.85->47.02, 0.95->format-error) so each rung is a
    # direct bare-vs-verbose delta on the same-day grader. bare is ~1.35-2.3x
    # faster per candidate, so N=budget*margin/lat is higher at every margin ->
    # the whole margin->score curve shifts up; the moonshot tests whether bare's
    # faster replay now LANDS where verbose format-errored (m0.95).
    "bare_canary_m055_cap1100": Rung(
        name="bare_canary_m055_cap1100",
        budget_margin=0.55,
        hard_n_cap=1100,
        description="bare canary: validates gemma+bare fire on the real grader; verbose scored 30.57 here",
    ),
    "bare_step_m072_cap1500": Rung(
        name="bare_step_m072_cap1500",
        budget_margin=0.72,
        hard_n_cap=1500,
        description="bare moderate step",
    ),
    "bare_step_m085_cap1800": Rung(
        name="bare_step_m085_cap1800",
        budget_margin=0.85,
        hard_n_cap=1800,
        description="bare aggressive step; verbose scored 47.02 here -> bare should clear it, maybe >55.8",
    ),
    "bare_moonshot_m095_cap2000": Rung(
        name="bare_moonshot_m095_cap2000",
        budget_margin=0.95,
        hard_n_cap=2000,
        description="bare moonshot: verbose FORMAT-ERRORED at m0.95; does bare's faster replay land here (>55.8)?",
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
