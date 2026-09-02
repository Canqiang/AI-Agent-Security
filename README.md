# The Scored Attack Surface Collapses to a Single Predicate

Code and research behind the [Working Note](docs/working-note-attack-surface.md) of
the same name, for the Kaggle competition
**[AI Agent Security: Multi-Step Tool Attacks](https://www.kaggle.com/competitions/ai-agent-security-multi-step-tool-attacks)**
(OpenAI · Google · IEEE).

**Author:** Xander (Kaggle [`canqiang`](https://www.kaggle.com/canqiang)) ·
**Working Note DOI:** [10.34740/kaggle/w/104679](https://doi.org/10.34740/kaggle/w/104679)

## What this is

The competition asks entrants to attack two tool-using agents (GPT-OSS-20B and a
Gemma 26B agent) in a deterministic offline sandbox, scored on four failure
predicates: exfiltration, untrusted-content-to-action, destructive writes, and
confused-deputy behavior. This repository derives the *reachable* attack surface
directly from the `aicomp-sdk` 3.1.2 source, checks it against live submissions,
and argues that the public benchmark collapses to a single scoring route.

The central claim (full argument in the [Working Note](docs/working-note-attack-surface.md)):

- Under the public guardrail, **only EXFILTRATION is both reachable and
  economically competitive** — one clean `http.post` whose `data` carries a
  plaintext sentinel, worth 18 raw points.
- `UNTRUSTED_TO_ACTION` and `DESTRUCTIVE_WRITE` are **structurally unreachable**:
  the guardrail's taint/deny window subsumes the scorer's provenance window, so
  any trace the scorer would reward is denied first and recorded `ok=False`.
- `CONFUSED_DEPUTY` is reachable but **economically dominated** on the public
  throughput metric.
- The public competition is therefore a **throughput problem**, not a search for
  new attacks.

## The final result

The competition closed on **1 September 2026**, and the private leaderboard
confirmed the note's central prediction (§8, §9): the prize-determining private
guardrail is payload-aware, so the disclosed public exfiltration method scores
near zero under it. **2,855 of 4,252 teams scored exactly 0.000** on the private
board, and the public frontier collapsed and reshuffled:

| Standing | Public | Private (final) |
|---|---|---|
| Public #1 | 147.530 | rank 6 · 37.690 |
| Public #2 | 143.930 | **rank 4,237 · 0.000** |
| **This entry** | rank 596 · 89.700 | **rank 270 · 11.915** |

Every exfiltration submission scored 0.000 privately. The one route that survived
was `CONFUSED_DEPUTY` — the predicate the *public* economics dominated away. A
single deliberate benign `email.send` hedge scored an identical 11.915 on both
boards and, selected as a final submission, set the final standing at rank
270/4,252 while the exfiltration route scored zero. See
[§7.6 of the Working Note](docs/working-note-attack-surface.md).

## Repository map

| Path | Contents |
|---|---|
| [`docs/working-note-attack-surface.md`](docs/working-note-attack-surface.md) | The Working Note — the primary deliverable. |
| `docs/` | Supporting research: SDK scoring reverse-engineering, guardrail code analysis, competition-research updates, and design specs. |
| `src/attack.py` | The scored attack: single-hop validation-fill exfiltration with Harmony-template analysis-channel forging. |
| `tools/` | Audit, submission, and probe tooling. `verify_reachability_closures.py` is the portable reachability check. |
| `notebooks/` | Attack and probe notebooks. |
| `research/`, `submissions/manifests/` | Supporting scripts and submission metadata / ledger. |

## Reproducing the core claim (no GPU)

The two structural closures (§5.2 / §5.3 of the note) run against the real SDK on CPU:

```bash
pip install aicomp-sdk==3.1.2
python tools/verify_reachability_closures.py
```

This calls the SDK's own `Guardrail.decide` and `eval_predicates` on synthetic
traces and asserts that `UNTRUSTED_TO_ACTION` and `DESTRUCTIVE_WRITE` can never
fire. The pinned SDK source is listed in the note's Appendix C.

## Scope and responsible use

This is offensive-security research on a **deliberately vulnerable, offline
benchmark** built for the competition. All experiments target that sandbox only —
no real systems, users, or data. Note that the forged-Harmony analysis-channel
primitive studied here is portable to any real Harmony-templated deployment; it
is published, after the competition's close, for defensive and benchmark-design
research, not for use against live systems.

## Citation

> Xander. *The Scored Attack Surface Collapses to a Single Predicate.* Kaggle
> Working Note, AI Agent Security: Multi-Step Tool Attacks, 2026.
> DOI [10.34740/kaggle/w/104679](https://doi.org/10.34740/kaggle/w/104679).

## License

Released under the [MIT License](LICENSE). The underlying `aicomp-sdk` is a
separate MIT-licensed project by the competition organizers.
