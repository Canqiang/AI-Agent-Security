"""Phase 0 forensics: pull Kaggle submissions, classify outcomes, write durable
per-ref manifests and a rollup ledger.

Network-free core: build_ledger() takes already-fetched records so it is fully
unit-testable. main() fetches via the Kaggle API and writes files.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import submission_taxonomy as st
from kaggle_status import (
    DEFAULT_COMPETITION,
    fetch_submissions,
    normalize_submission,
    now_iso,
)

REF_SCHEMA = "2026-06-24.submission-ref.v1"
LEDGER_SCHEMA = "2026-06-24.submission-ledger.v1"
DEFAULT_OUT_DIR = TOOLS.parent / "submissions" / "manifests"
_TERMINAL_TAX = {"complete_scored", "complete_zero", "runtime_exceeded",
                 "system_error", "other_error"}


def _ref_key(record: dict) -> str:
    return str(record.get("ref"))


def build_ref_manifest(
    record: dict, *, taxonomy: str, now: str, existing: dict | None, log_excerpt: str | None
) -> dict:
    first_seen = (existing or {}).get("first_seen_at", now)
    resolved_at = (existing or {}).get("resolved_at")
    if taxonomy in _TERMINAL_TAX and resolved_at is None:
        resolved_at = now
    return {
        "schema_version": REF_SCHEMA,
        "ref": record.get("ref"),
        "competition": record.get("competition") or DEFAULT_COMPETITION,
        "kernel": record.get("kernel"),
        "kernel_version_url": record.get("url"),
        "submitted_at": record.get("date"),
        "description": record.get("description") or "",
        "status": record.get("status"),
        "taxonomy": taxonomy,
        "public_score": st.score_value(record.get("public_score")),
        "private_score": st.score_value(record.get("private_score")),
        "error_description": record.get("error_description") or "",
        "log_excerpt": log_excerpt if log_excerpt is not None
        else (existing or {}).get("log_excerpt"),
        "first_seen_at": first_seen,
        "resolved_at": resolved_at,
        "notes": (existing or {}).get("notes", ""),
    }


def build_ledger(
    records: list[dict],
    *,
    existing: dict[str, dict],
    now: str,
    log_fetcher: Callable[[dict, str], str | None] | None = None,
) -> tuple[dict[str, dict], dict]:
    manifests: dict[str, dict] = dict(existing)
    for record in records:
        key = _ref_key(record)
        taxonomy = st.classify(record)
        prior = existing.get(key)
        log_excerpt = None
        if log_fetcher is not None and taxonomy in {
            "runtime_exceeded", "system_error", "other_error", "complete_zero"
        } and (prior is None or prior.get("log_excerpt") is None):
            log_excerpt = log_fetcher(record, taxonomy)
        manifests[key] = build_ref_manifest(
            record, taxonomy=taxonomy, now=now, existing=prior, log_excerpt=log_excerpt
        )
    summary = st.summarize(list(manifests.values()))
    baseline_ref = None
    for m in manifests.values():
        if m["taxonomy"] == "complete_scored":
            baseline_ref = m["ref"]  # last (most recent if records date-desc)
            break
    ledger = {
        "schema_version": LEDGER_SCHEMA,
        "competition": DEFAULT_COMPETITION,
        "updated_at": now,
        "counts_by_taxonomy": summary["counts_by_taxonomy"],
        "best_public_score": summary["best_public_score"],
        "best_scored_ref": summary["best_scored_ref"],
        "current_baseline_ref": baseline_ref,
        "unresolved_pending_refs": summary["unresolved_pending_refs"],
        "refs": sorted(
            (
                {
                    "ref": m["ref"], "submitted_at": m["submitted_at"],
                    "taxonomy": m["taxonomy"], "public_score": m["public_score"],
                    "description": m["description"],
                }
                for m in manifests.values()
            ),
            key=lambda r: str(r["submitted_at"] or ""),
            reverse=True,
        ),
    }
    return manifests, ledger


def load_existing(out_dir: Path) -> dict[str, dict]:
    existing: dict[str, dict] = {}
    if not out_dir.exists():
        return existing
    for path in out_dir.glob("ref-*.json"):
        try:
            data = json.loads(path.read_text())
            existing[str(data.get("ref"))] = data
        except Exception:
            continue
    return existing


def write_ledger(out_dir: Path, manifests: dict[str, dict], ledger: dict) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for key, manifest in manifests.items():
        (out_dir / f"ref-{key}.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    (out_dir / "ledger.json").write_text(
        json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def fetch_records(api: Any, competition: str, page_size: int) -> list[dict]:
    raw = fetch_submissions(api, competition, page_size)
    return [normalize_submission(item) for item in raw]


def make_log_fetcher(api: Any, kernel: str | None, mode: str) -> Callable[[dict, str], str | None] | None:
    if mode == "never" or not kernel:
        return None

    def fetch(record: dict, taxonomy: str) -> str | None:
        import tempfile
        try:
            with tempfile.TemporaryDirectory() as tmp:
                api.kernels_output(kernel, path=tmp, quiet=True)
                logs = list(Path(tmp).glob("*.log"))
                if not logs:
                    return None
                text = logs[0].read_text(errors="replace")
                return text[-4000:]
        except Exception as exc:  # best-effort diagnostic only
            return f"<log fetch failed: {exc}>"

    return fetch


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--competition", default=DEFAULT_COMPETITION)
    parser.add_argument("--kernel", default="canqiang/aiagsec-submission")
    parser.add_argument("--page-size", type=int, default=25)
    parser.add_argument("--pull-logs", choices=("auto", "always", "never"), default="auto")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--print", action="store_true")
    args = parser.parse_args()

    from kaggle.api.kaggle_api_extended import KaggleApi

    api = KaggleApi()
    api.authenticate()
    records = fetch_records(api, args.competition, args.page_size)
    log_mode = "never" if args.pull_logs == "never" else args.pull_logs
    log_fetcher = make_log_fetcher(api, args.kernel, log_mode)
    existing = load_existing(args.out_dir)
    manifests, ledger = build_ledger(
        records, existing=existing, now=now_iso(), log_fetcher=log_fetcher
    )
    write_ledger(args.out_dir, manifests, ledger)
    if args.print:
        print(json.dumps(ledger, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
