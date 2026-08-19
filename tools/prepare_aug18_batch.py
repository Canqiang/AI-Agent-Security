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
    # ===== 2026-08-19 batch =====
    # Lesson from 08-18: overshoot (partial-credit) WORKS (89.535 = #317);
    # gemma fast-row multipost (burst OR forge) is a DISASTER (-20pts). So ALL
    # variants keep FAST_MULTIPOST_N=1 (gemma single-post) and only vary the
    # gpt_oss slow-row multipost N + overshoot aggressiveness. base_recipe bakes
    # SPLIT_BY_LATENCY=True + SLOW_MULTIPOST_N=5 + REPLAY_SAFE_SIZING=True +
    # MARGIN_S=90 + MARGIN_FLOOR_MIN=15 (src defaults) — S1 reproduces 89.535.

    # S1 保底: exact reproduction of the 89.535 winner (fill 0.99 / replay 1.0).
    "overshoot-r1": {
        "desc": "reproduce 08-18 winner: fill 0.99 / replay 1.0 / mpost5 / gemma single-post",
        "slug": "overshoot-r1",
        "knobs": {
            "FILL_BUDGET_FRAC": (0.99, "08-19 r1: exact 89.535 reproduction"),
            "REPLAY_SAFE_FRAC": (1.0, "08-19 r1: exact 89.535 reproduction"),
            "FAST_MULTIPOST_N": (1, "08-19 r1: gemma single-post (multipost is a loss)"),
        },
    },
    # S2 激进 margin+fill: align evgendvorkin's aggressive MARGIN_S=35, push fill
    # to 0.995 (between our 0.99 and his 0.998). gemma stays single-post.
    "overshoot-m35-f995": {
        "desc": "overshoot + MARGIN 35 + fill 0.995 (aggressive, gemma single-post)",
        "slug": "overshoot-m35-f995",
        "knobs": {
            "MARGIN_S": (35.0, "08-19 m35: aggressive margin (evgendvorkin-aligned)"),
            "FILL_BUDGET_FRAC": (0.995, "08-19 m35: fill between 0.99 and 0.998"),
            "REPLAY_SAFE_FRAC": (1.0, "08-19 m35: partial-credit replay"),
            "FAST_MULTIPOST_N": (1, "08-19 m35: gemma single-post"),
        },
    },
    # S3 gpt_oss multipost N=6: test whether N=6 beats N=5 on the slow row.
    "overshoot-mpost6": {
        "desc": "overshoot + gpt_oss multipost N=6 (gemma single-post)",
        "slug": "overshoot-mpost6",
        "knobs": {
            "SLOW_MULTIPOST_N": (6, "08-19 mpost6: gpt_oss multipost N=6"),
            "FILL_BUDGET_FRAC": (0.99, "08-19 mpost6: winner fill"),
            "REPLAY_SAFE_FRAC": (1.0, "08-19 mpost6: partial-credit replay"),
            "FAST_MULTIPOST_N": (1, "08-19 mpost6: gemma single-post"),
        },
    },
    # S4 gpt_oss multipost N=4 + empty-closing: N-curve low end + shorter forged
    # analysis (both directions isolated vs S1/S3).
    "overshoot-mpost4-ec": {
        "desc": "overshoot + gpt_oss multipost N=4 + empty closing (gemma single-post)",
        "slug": "overshoot-mpost4-ec",
        "knobs": {
            "SLOW_MULTIPOST_N": (4, "08-19 mpost4: gpt_oss multipost N=4"),
            "SLOW_MULTIPOST_EMPTY_CLOSING": (True, "08-19 mpost4: drop trailing closing sentence"),
            "FILL_BUDGET_FRAC": (0.99, "08-19 mpost4: winner fill"),
            "REPLAY_SAFE_FRAC": (1.0, "08-19 mpost4: partial-credit replay"),
            "FAST_MULTIPOST_N": (1, "08-19 mpost4: gemma single-post"),
        },
    },
    # S5 maxfill: most aggressive fill (0.998, evgendvorkin-aligned) at MARGIN 47.
    "overshoot-maxfill": {
        "desc": "overshoot + fill 0.998 + MARGIN 47 (max overshoot, gemma single-post)",
        "slug": "overshoot-maxfill",
        "knobs": {
            "MARGIN_S": (47.0, "08-19 maxfill: proven mpost5 margin"),
            "FILL_BUDGET_FRAC": (0.998, "08-19 maxfill: fill to the absolute wall"),
            "REPLAY_SAFE_FRAC": (1.0, "08-19 maxfill: partial-credit replay"),
            "FAST_MULTIPOST_N": (1, "08-19 maxfill: gemma single-post"),
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
