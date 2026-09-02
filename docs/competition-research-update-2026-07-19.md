# Kaggle Competition Incremental Research: AI Agent Security — Multi-Step Tool Attacks (2026-07-19 update)

> Date: 2026-07-19. Previous research: `docs/competition-research-update-2026-07-17.md` (2026-07-17). The two things in between on 07-18 — the TDD implementation of the replay-safe sizing mechanism, and a two-track intelligence recon on the same day (`frontier-technique-research-2026-07-18`) — were recorded only in Claude memory and never turned into docs/ documents; this update is the score record of the batch of submissions fired on 07-18 plus the follow-up actions. It does not re-expand the 07-18 recon content, only citing its conclusions where needed and flagging corrections.
> This update's conclusions come from: ① directly querying the Kaggle API (`tools/pull_submission_ledger.py` + full paginated traversal of the leaderboard) to verify scores and rankings, not relying on the paginated preview or the second-hand restatement of the intelligence recon; ② real verification on our own live submission pipeline (5 new real submissions this round, all PENDING, to be verified next time); ③ comparing one specific assertion from the 07-18 recon ("the disclosed replay-safe operating point is 0.92-0.94") against the real scoring data from our own pipeline, and finding that this assertion does not apply to our own implementation.

---

## 0. The most important sentences this round

1. **The 5-shot replay-safe sizing gradient fired on 07-18 all scored, top score 63.850→75.825→85.5, a three-level jump, and all were obtained by stacking different engineering techniques on the same "Harmony token forgery + latency-based routing" mechanism.** r097 (nominal `REPLAY_SAFE_FRAC=0.97`, effectively about 0.957 after subtracting the measured warmup) scored **85.5, a new all-time high**, jumping the ranking from 217-222/2020-2022 to **about 113-114/2067** (exactly 4 teams tied at 85.500).
2. **r098/r099a/r099b (effective frac ≥0.967) all voided with "format error", and r095 (effective ~0.937) also produced a high score of 84.78.** This pins the real voiding boundary of the "replay-safe" mechanism on our own pipeline between **effective 0.957 (safe) and 0.967 (void)**.
3. **This boundary is clearly higher than the third-party "disclosed safe point 0.92-0.94" cited in the 07-18 recon.** That number was measured by a scraped third-party repo (`Manish-khichar/JED-Attack`) on **their own** engine, not the real boundary of our pipeline — the warmup-subtraction design in our `_fill()` (subtract the measured warmup from the replay budget first, then multiply by frac) buys more real buffer than the other side's naive "nominal frac × fixed budget" implementation. **Lesson: externally disclosed calibration numbers can only serve as a prior; they must be overridden by real scores from our own pipeline, and we cannot assume we should keep being conservative.**
4. **The EV estimate hand-computed on 07-18 was wrong in both direction and magnitude**: at the time we estimated "0.99 only adds ~+3% N over fm04/f095 (~+2 points)", but on one clamp that actually landed (r097) the gain was **+9.675 points (relative to 75.825), nearly 5× the predicted ceiling**. For this kind of boundary-effect payoff, hand-computed extrapolation is unreliable; only measured numbers can be trusted.
5. **Striking while the iron is hot, we used today's fresh 5/5 quota to fire a 5-point boundary bisection gradient** (nominal 0.971/0.973/0.975/0.977/0.979, interpolating between the known safe point 0.97 and the known void point 0.98), all submitted successfully with no 403, awaiting scores — the goal is to narrow the coarse interval "effective 0.957 safe ~ 0.967 void" to a more precise number.
6. **Along the way, we used Kaggle API pagination to verify the full leaderboard structure** (not the paginated preview, but actually flipping through all 2067 teams), confirming a detail of the ranking methodology: the leaderboard displays "each team's highest score", and tied scores get crammed into adjacent row numbers — this round we have 4 teams tied at 85.500, and under Kaggle's official ranking algorithm they will most likely show as the same rank (about 113), not the 114th row we counted by paging.

---

## 1. 07-18 gradient score details

The `fill_rsafe_split_*` 5-shot fired on 07-18 (all split routing + Harmony token + floor_min=4/m47/f0.95 fallback, varying only `REPLAY_SAFE_FRAC`) all resolved:

| Variant | Nominal frac | Effective frac (warmup subtracted) | ref | Result |
|---|---:|---:|---|---|
| r099a | 0.99 | ~0.977 | `54797683` | Format error (void) |
| r099b | 0.99 | ~0.977 | `54797708` | Format error (void) |
| r098 | 0.98 | ~0.967 | `54797729` | Format error (void) |
| r097 | 0.97 | ~0.957 | `54797743` | **85.5 ✅ new all-time high** |
| r095 | 0.95 | ~0.937 | `54797753` | 84.78 |

Verified directly with `tools/pull_submission_ledger.py --print`: `best_public_score=85.5`, `best_scored_ref=54797743`; `submissions/manifests/` is synced (commit `f7e0738`).

**Ranking verification method**: since the Kaggle paginated preview only shows the first 20 rows, this round we directly called the underlying `ApiGetLeaderboardRequest` (bypassing the `competition_leaderboard_view()` wrapper limitation that doesn't return `next_page_token`) to page through all 2067 teams, then matched ourselves in the result by `team_id` (`Xander`, `team_id=16378320`). The hit position was row 114, score `85.500`; 3 other teams share the same score (`kwang` row 113, `Dante Lok` row 115, `zekenoe` row 116) — 4 teams tied at the same `85.500`. Under Kaggle's official standard competition ranking (ties share a rank, the next rank skips by the number of ties), these 4 teams most likely all show as rank 113, and our internal record uses "about 113-114" to represent this uncertainty.

---

## 2. Voiding boundary: our own measured data overturns the externally disclosed calibration value

The 07-18 recon (`frontier-technique-research-2026-07-18`, never turned into a docs/ document, only in memory) cited a claim from a third-party repo (`Manish-khichar/JED-Attack`, file `ai-agent-security-v80-tensorliu-stacked3-v85.ipynb`): `REPLAY_SAFE=0.99` blows up the return set and triggers "format error", and **the disclosed safe operating points are aggressive 0.94, conservative 0.92**. Based on this, we judged that the gradient we fired (nominal 0.99/0.99/0.98/0.97/0.95) "aimed too high", and expected that only r095 (effective ~0.937, landing in the disclosed 0.92-0.94 safe band) was most likely to land, while r097/098/099 had voiding risk.

**After the actual scores came in, this expectation was overturned**: r097 at effective ~0.957 not only landed cleanly but also produced the highest score of the whole batch; the real voiding boundary (on our own pipeline) falls between effective 0.957 and 0.967 — at least two-plus percentage points higher than the third-party's disclosed 0.92-0.94.

**Presumed reason**: that third-party number was measured on **their own** fill engine, not a universal constant. When our `src/attack.py::_fill()` replay-safe implementation computes the stopping point, it first **subtracts the measured warmup time** from "nominal frac × 9000s replay budget", then accumulates the measured replay cost of retained candidates against that to decide whether to keep filling; this "subtract warmup first, then multiply by frac" design buys a slice of real buffer that the other side's naive "nominal frac directly times fixed budget" implementation doesn't — so the same nominal 0.97 frac yields lower real risk on our pipeline than on theirs.

This does not mean the third-party number is wrong (it is probably accurate for their own engine); rather, **any "safety boundary" number carried over cross-repo / cross-implementation is essentially a product of the other side's engineering details and cannot be treated directly as a physical constant of our own code**. This has been written into the `frontier-technique-research-2026-07-18` correction already in Claude memory, and into this repo's `docs/working-note-attack-surface.md` (as an incidental methodological observation, even though that Working Note's main-line argument is about something else).

---

## 3. Hand-computed EV vs. measured: how wildly wrong it was

Before firing the gradient on 07-18, we hand-computed EV once: estimating at real gpt_oss ~20s/candidate, replay-safe 0.99 could only squeeze out **~+3% more candidate count N, about +2 points** over the then-best config (`fill_split_fm04_m47_f095`, 75.825) — and based on this we judged that the lever itself was marginal, and that pushing into 80+ mostly depended on drawing a good result within the ~20-26% same-config noise band, not on a deterministic gain this mechanism alone could provide.

**After it actually landed**: r097 (a clamp that actually landed, not one of the three that voided) gained **+9.675 points** over 75.825, **nearly 5×** the predicted ceiling (+2 points). The hand-computed model clearly underestimated: it approximated N's growth as linear, but did not adequately model the nonlinear amplification effect on candidate count of "the fill loop's stopping point being pinned tight against the real replay budget edge, rather than stopping early like a flat floor_min cushion".

**Conclusion**: for this kind of "extract throughput hugging the boundary" lever, hand-computed EV can only give a directional, extremely unreliable lower-bound reference, and the actual payoff must be spoken for by real submission data. Next time a similar boundary-effect estimate comes up, we should admit the hand-computation's uncertainty earlier, rather than treating a rough lower bound as a decision basis.

---

## 4. The boundary bisection gradient fired today (07-19)

The user explicitly chose "go all-in on boundary probing": since the known safe boundary is much more lenient than expected (effective 0.957 safe vs 0.967 void, not 0.92-0.94), today's fresh 5/5 quota is all used to finely locate this boundary, rather than re-confirming r097 or pivoting to some other research direction.

We took 5 interpolation points between the known safe point (nominal 0.97) and the known void point (nominal 0.98), evenly distributed, with everything else identical to r097 (split routing + Harmony token + floor_min=4/m47/f0.95 fallback + replay_safe_sizing=True, varying only `REPLAY_SAFE_FRAC`):

| Variant | Nominal frac | ref |
|---|---:|---|
| `fill_rsafe_split_r0971` | 0.971 | `54820123` |
| `fill_rsafe_split_r0973` | 0.973 | `54820139` |
| `fill_rsafe_split_r0975` | 0.975 | `54820087` |
| `fill_rsafe_split_r0977` | 0.977 | `54820150` |
| `fill_rsafe_split_r0979` | 0.979 | `54820172` |

**Generation method**: rather than following the past pattern of "temporarily editing `KERNEL_ID`/`KERNEL_TITLE`/`RUNGS` in `tools/prepare_live_fill_variants.py` then `git checkout` to restore", we wrote a one-off script that directly `import prepare_live_fill_variants`, monkeypatches `KERNEL_ID`/`KERNEL_TITLE` in-process, and calls its `write_variant()`/`Rung` API — the effect is equivalent (that module was designed as an importable API and is covered by unit tests to begin with), but from start to finish it never touches git-tracked files, keeping `git status` clean throughout and avoiding the risk of a manual-revert mistake.

**Push**: diagnostics first — first fire only the middle point `r0975` to confirm the pipeline (get a ref, no 403), then push the remaining 4 one at a time — `push_submit_variants.py` only takes one `--kernel` per call for the wait/validate/formal-submit steps, so the 5 variants' each-independent private slugs must be pushed in 5 separate calls, not passing multiple variant names at once. All `ok:true`, `stage:submitted`, `blockers:[]`, no 403. Two repo ledger sync commits: `f7e0738` (85.5 score sync) + `ab15df7` (record this batch of new pending).

**How to read the next step**: if the two high-nominal ones (0.977/0.979) void and the two low-nominal ones (0.971/0.973) land, we can narrow the boundary from the coarse interval "effective 0.957 safe ~ 0.967 void" to a more precise number (most likely precise to some specific hundredth); if the boundary is not this clean (e.g. some middle point unexpectedly voids while both ends land), that indicates the boundary itself also has a same-config noise component and is not a pure deterministic threshold, and it must be read against the historical lesson of "the floor_min sweep produced non-monotonic format errors" (`scored-submission-ledger` 07-10 entry).

---

## 5. To watch / next steps

- **Check the scores of these 5 new submissions** (historically 2.5-4.5 hours or more, sometimes longer).
- **Still not done**: repeat r097 verbatim once to fully confirm the reliability of 85.5 (the current evidence is "two independent draws at two different nominal fracs both land in the 84-86 range, differing from each other by <1 point, much narrower than the historical noise band" — this is supporting evidence but not a same-config repeat itself).
- **Still-unread high-signal intelligence**: `yusuketogashi/ai-agent-sec-another-approach` (a new notebook flagged in the 07-17 recon, 112 votes, unread — the score isn't exposed via the API, and the code doesn't render through r.jina.ai, so it needs a manual browser open).
- **The 88-103 top tier remains a black box**: the rank-2 player (102.835, forum post 726264) explicitly says this gap "has a clear direction", i.e. deterministic technique, not GPU luck; the disclosed recipe family's own highest ancestor version reportedly reached 87.9. Multi-post stacking is currently the only surviving candidate hypothesis (Pilkwang says stacking "is dead", but new notebooks like devchandra/tensorliu's "Stacked-3 v85" are still testing it live), with no public verified score confirming it yet.
- `docs/working-note-attack-surface.md` §7/§9/§11 already has a 2026-07-19 update paragraph added, correcting the old conclusion "the CoT compression lever tested null in one shot" to "what tested null was the wrong specific implementation (natural-language framing); the real implementation (token-level forgery) has been confirmed effective" — this is the only English deliverable in this repo that needs to maintain academic rigor, and any further score changes going forward should be synced back to that document, not just this Chinese research record.
