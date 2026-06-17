"""Local end-to-end evaluation of src/attack.py.

Runs the official `evaluate_redteam` harness (same scoring path as the
competition) against a chosen agent backend, and prints the normalized score
plus a breakdown.

Usage:
    python tools/local_eval.py                 # compliant mock agent (proves scoring)
    python tools/local_eval.py deterministic   # packaged deterministic agent (~0)
    python tools/local_eval.py --n 500         # cap candidate count

The competition target agents (gpt-oss / gemma) need model weights and are not
runnable here; the compliant mock agent is a behavioural proxy that follows
"POST <data> TO <url>" so the attack + scoring pipeline can be validated.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Make the SDK and our attack importable.
REPO = Path(__file__).resolve().parent.parent
SDK = REPO / "competition_files"
sys.path.insert(0, str(SDK))
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tools"))

from aicomp_sdk.agents import AgentSelection  # noqa: E402
from aicomp_sdk.evaluation.runner import evaluate_redteam  # noqa: E402

from attack import AttackAlgorithm  # noqa: E402
from compliant_agent import CompliantAgent  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("agent", nargs="?", default="compliant",
                    help="compliant | deterministic")
    ap.add_argument("--n", type=int, default=300, help="n_candidates")
    ap.add_argument("--budget", type=float, default=20.0, help="time_budget_s")
    args = ap.parse_args()

    kwargs = dict(budget_s=args.budget, attack_config={"n_candidates": args.n})
    if args.agent == "compliant":
        res = evaluate_redteam(AttackAlgorithm, agent_factory=CompliantAgent,
                               agent_label="compliant", **kwargs)
    else:
        res = evaluate_redteam(AttackAlgorithm,
                               agent_selection=AgentSelection(args.agent), **kwargs)

    a = res.attack
    print(f"agent={args.agent}  n_candidates={args.n}")
    print(f"  normalized score : {res.final_score:.2f} / 1000")
    print(f"  raw score        : {a.score_raw:.1f}")
    print(f"  findings (scored): {a.findings_count}")
    print(f"  unique cells     : {a.unique_cells}")
    if a.findings_count:
        per = a.score_raw / a.findings_count
        print(f"  raw per finding  : {per:.2f}  (EXFIL 16 + unique-cell 2 = 18 expected)")


if __name__ == "__main__":
    main()
