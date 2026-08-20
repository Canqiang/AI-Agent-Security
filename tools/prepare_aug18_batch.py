"""Build the 2026-08-18 five-submission batch after the 08-06 evaluator update.

Context (08-06 update, thread 733058): gemma tool-call parsing fixed (gemma can
now multi-step), and replay timeouts preserve partial scores (no more 0.0 wipe).
The old 91.03 submission was rescored ERROR and dropped from the leaderboard; our
live best is 88.255. The proven mpost5 recipe (fill_r097_mpost5) is the baseline;
variants overshoot the replay cushion (partial-credit makes under-fill the bigger
loss) and enable gemma multipost (FAST_MULTIPOST_N) on the fast row.

Each variant bakes its knobs into a fresh private kernel with a unique slug, so
all five can be pushed without slug-collision (memory feedback-new-private-notebook-per-submission).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SRC = REPO / "src" / "attack.py"
BASE_NOTEBOOK = REPO / "notebooks" / "submission.ipynb"
OUT_ROOT = REPO / "kaggle_push" / "submission_variants"


def substitute_once(text: str, const: str, value: int | float | bool, comment: str) -> str:
    pattern = re.compile(
        rf"^{re.escape(const)} = (?:[0-9.]+|True|False)([ \t]*#.*)?$",
        re.MULTILINE,
    )
    new_line = f"{const} = {value}       # {comment}"
    text, n = pattern.subn(lambda _m: new_line, text)
    if n != 1:
        raise ValueError(f"expected exactly one {const} assignment, found {n}")
    return text


def build_variant(
    name: str,
    knobs: dict[str, tuple[int | float | bool, str]],
    *,
    desc: str,
    slug: str | None = None,
) -> Path:
    # Base is the current src/attack.py, which carries the NEW FAST_MULTIPOST_N
    # knob plus the engine defaults. The proven mpost5 recipe (91.03 lineage,
    # fill_r097_mpost5) is SPLIT_BY_LATENCY=True + SLOW_MULTIPOST_N=5 +
    # REPLAY_SAFE_SIZING=True -- bake that in for EVERY variant, then sweep only
    # the listed knobs on top. This keeps the byte-identical mpost5 recipe as the
    # baseline (S1) and isolates today's levers (overshoot, gemma multipost).
    code = SRC.read_text(encoding="utf-8")
    base_recipe = {
        "SPLIT_BY_LATENCY": (True, "08-18 base: mpost5 proven recipe"),
        "SLOW_MULTIPOST_N": (5, "08-18 base: mpost5 proven recipe"),
        "REPLAY_SAFE_SIZING": (True, "08-18 base: mpost5 proven recipe"),
    }
    for const, (value, comment) in base_recipe.items():
        code = substitute_once(code, const, value, comment)
    for const, (value, comment) in knobs.items():
        code = substitute_once(code, const, value, comment)

    notebook = json.loads(BASE_NOTEBOOK.read_text(encoding="utf-8"))
    code_cell = notebook["cells"][2]
    source = "%%writefile /kaggle/working/attack.py\n" + code
    code_cell["source"] = [line + "\n" for line in source.splitlines()]
    code_cell["outputs"] = []
    code_cell["execution_count"] = None

    slug = slug or name
    metadata = {
        "code_file": "submission.ipynb",
        "competition_sources": ["ai-agent-security-multi-step-tool-attacks"],
        "dataset_sources": [],
        "enable_gpu": True,
        "enable_internet": False,
        "enable_tpu": False,
        "id": f"canqiang/aiagsec-{slug}",
        "is_private": True,
        "kernel_sources": [],
        "kernel_type": "notebook",
        "language": "python",
        "machine_shape": "NvidiaTeslaT4",
        "title": f"AIAgSec {slug}",
    }

    out_dir = OUT_ROOT / name
    out_dir.mkdir(parents=True, exist_ok=True)
    out_dir.joinpath("attack.py").write_text(code, encoding="utf-8")
    out_dir.joinpath("submission.ipynb").write_text(
        json.dumps(notebook, indent=1) + "\n", encoding="utf-8"
    )
    out_dir.joinpath("kernel-metadata.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    manifest = {
        "name": name,
        "chain_k": 1,
        "mode": "live_validation_fill_overshoot",
        # n_candidates is the SDK display cap; the live fill self-sizes to the
        # 9000s budget, so 2000 is the correct ceiling (== HARD_N_CAP).
        "n_candidates": 2000,
        "expected_public_score": None,
        "description": desc,
        "knobs": {k: v[0] for k, v in knobs.items()},
        "folder": str(out_dir),
        "notebook": str(out_dir / "submission.ipynb"),
        "metadata": str(out_dir / "kernel-metadata.json"),
        "source": str(out_dir / "attack.py"),
    }
    out_dir.joinpath("variant-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return out_dir


VARIANTS: dict[str, dict] = {
    # ===== 2026-08-20 batch (council verdict: H1 dose-response sweep) =====
    # LLM-council ruling on the 115-137 band: composite mechanism, with the
    # post-08-06 +25 jump (111.8 -> 137.1) most plausibly = replay-overshoot x
    # partial credit (H1, 35%) or gemma-native multipost (H2, 30%), on an H4-shaped
    # pre-update base (~80% present). The decisive, never-run experiment is
    # REPLAY_OVERSHOOT_FRAC > 1.0 (new knob, decoupled from the FILL wall so the
    # gen phase cannot overrun -- 08-06 made replay timeout bank partial credit
    # while gen timeout stays fatal). Dose-response 1.1/1.3/1.6 on the EXACT
    # 89.535 config: monotone rise = real multiplier; flat/void = H1 is variance
    # only. Slot 4 = byte-identical anchor repeat (noise calibration + harvest);
    # slot 5 = maxfill 2nd draw (per-row decomposition shows gemma already carries
    # ~46% of posts -> verdict's rule picks maxfill over a gemma-mpost arm).
    # All variants keep the 08-18 winner base: fill 0.99 / REPLAY_SAFE_FRAC 1.0 /
    # mpost5 / gemma single-post.

    "overshoot11": {
        "desc": "H1 dose-response 1.1: fill 0.99 / wall 1.0 / replay-overshoot 1.1 (partial-credit)",
        "slug": "overshoot11",
        "knobs": {
            "FILL_BUDGET_FRAC": (0.99, "08-20 base: 89.535 winner config"),
            "REPLAY_SAFE_FRAC": (1.0, "08-20 base: fill wall anchored at 1.0 (gen must not overrun)"),
            "FAST_MULTIPOST_N": (1, "08-20 base: gemma single-post"),
            "REPLAY_OVERSHOOT_FRAC": (1.1, "08-20 H1: kept replay cost 1.1x budget (partial-credit gamble)"),
        },
    },
    "overshoot13": {
        "desc": "H1 dose-response 1.3: fill 0.99 / wall 1.0 / replay-overshoot 1.3 (partial-credit)",
        "slug": "overshoot13",
        "knobs": {
            "FILL_BUDGET_FRAC": (0.99, "08-20 base: 89.535 winner config"),
            "REPLAY_SAFE_FRAC": (1.0, "08-20 base: fill wall anchored at 1.0 (gen must not overrun)"),
            "FAST_MULTIPOST_N": (1, "08-20 base: gemma single-post"),
            "REPLAY_OVERSHOOT_FRAC": (1.3, "08-20 H1: kept replay cost 1.3x budget (partial-credit gamble)"),
        },
    },
    "overshoot16": {
        "desc": "H1 dose-response 1.6: fill 0.99 / wall 1.0 / replay-overshoot 1.6 (partial-credit)",
        "slug": "overshoot16",
        "knobs": {
            "FILL_BUDGET_FRAC": (0.99, "08-20 base: 89.535 winner config"),
            "REPLAY_SAFE_FRAC": (1.0, "08-20 base: fill wall anchored at 1.0 (gen must not overrun)"),
            "FAST_MULTIPOST_N": (1, "08-20 base: gemma single-post"),
            "REPLAY_OVERSHOOT_FRAC": (1.6, "08-20 H1: kept replay cost 1.6x budget (partial-credit gamble)"),
        },
    },
    "overshoot-anchor2": {
        "desc": "byte-identical repeat of the 89.535 winner (anchor + noise calibration + harvest)",
        "slug": "overshoot-anchor2",
        "knobs": {
            "FILL_BUDGET_FRAC": (0.99, "08-20 anchor: exact 89.535 reproduction"),
            "REPLAY_SAFE_FRAC": (1.0, "08-20 anchor: exact 89.535 reproduction"),
            "FAST_MULTIPOST_N": (1, "08-20 anchor: gemma single-post"),
        },
    },
    "overshoot-maxfill2": {
        "desc": "maxfill 2nd draw: fill 0.998 + MARGIN 47 / wall 1.0 (gemma already pulls ~46% -> maxfill over gemma-mpost)",
        "slug": "overshoot-maxfill2",
        "knobs": {
            "MARGIN_S": (47.0, "08-20 maxfill2: proven mpost5 margin"),
            "FILL_BUDGET_FRAC": (0.998, "08-20 maxfill2: fill to the wall"),
            "REPLAY_SAFE_FRAC": (1.0, "08-20 maxfill2: wall 1.0"),
            "FAST_MULTIPOST_N": (1, "08-20 maxfill2: gemma single-post"),
        },
    },
}


def main() -> int:
    for name, spec in VARIANTS.items():
        out_dir = build_variant(name, spec["knobs"], desc=spec["desc"],
                                slug=spec.get("slug"))
        print(f"{name}: {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
