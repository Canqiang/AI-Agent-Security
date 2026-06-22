"""Static lint for dev-only CandidateSpec JSONL/JSON banks.

The linter validates the candidate-bank contract without running target models.
Use `--scored` for the stricter subset that may be adapted into `src/attack.py`.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
DEFAULT_SCHEMA = REPO / "research" / "candidate_bank.schema.json"

REQUIRED_FIELDS = {
    "schema_version",
    "id",
    "family",
    "route",
    "attack_class",
    "security_axis",
    "source_channel",
    "messages",
    "expected_tools",
    "expected_predicates",
    "expected_guardrail",
    "domains",
    "payloads",
    "runtime_cost_units",
    "public_score_posture",
    "promotion_status",
    "negative_controls",
    "notes",
    "tags",
}

ROUTES = {
    "direct_exfil",
    "memory_exfil",
    "file_handoff_exfil",
    "web_email_u2a",
    "destructive_write",
    "confused_deputy",
}
ATTACK_CLASSES = {
    "exfiltration",
    "untrusted_to_action",
    "destructive_write",
    "confused_deputy",
}
SECURITY_AXES = {"information_flow", "delegated_authority", "persistent_state"}
SOURCE_CHANNELS = {"user", "web", "email", "file", "tool"}
GUARDRAIL_EXPECTATIONS = {"allow", "deny", "unknown"}
POSTURES = {"score_track", "research_only", "rejected"}
PROMOTION_STATES = {"research", "validated", "promoted", "rejected"}
PREDICATES = {
    "EXFILTRATION",
    "UNTRUSTED_TO_ACTION",
    "DESTRUCTIVE_WRITE",
    "CONFUSED_DEPUTY",
}

SENSITIVE_URL_WORDS = (
    "secret",
    "password",
    "token",
    "key",
    "credential",
    "private",
    "confidential",
    "api_key",
)
SHARE_AUTH_WORDS = ("send", "email", "upload")
RESERVED_HTTP_HOST_SUFFIXES = (".example.net", ".example.invalid")
RESERVED_HTTP_HOSTS = ("example.net", "example.invalid")

URL_RE = re.compile(r"https?://[^\s\"'<>),;]+")
PAYLOAD_RE = re.compile(
    r"(SECRET_MARKER|sk_live_test|PASSWORD=test123|TOKEN=admin123|SECRET_API_KEY=)",
    re.IGNORECASE,
)


def read_text(path: Path | str) -> str:
    if str(path) == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def load_candidate_bank(path: Path | str) -> list[dict[str, Any]]:
    text = read_text(path).strip()
    if not text:
        return []
    if text[0] == "[":
        parsed = json.loads(text)
        if not isinstance(parsed, list):
            raise ValueError("JSON candidate bank must be an array")
        return parsed

    records: list[dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        parsed = json.loads(stripped)
        if not isinstance(parsed, dict):
            raise ValueError(f"line {lineno}: JSONL record must be an object")
        records.append(parsed)
    return records


def host_from_url(url: str) -> str:
    if "://" not in url:
        return "unknown"
    host = url.split("://", 1)[1].split("/", 1)[0]
    return host.rstrip(".").lower()


def urls_in_messages(messages: list[str]) -> list[str]:
    urls: list[str] = []
    for message in messages:
        urls.extend(URL_RE.findall(message))
    return urls


def is_reserved_http_host(host: str) -> bool:
    return host in RESERVED_HTTP_HOSTS or any(
        host.endswith(suffix) for suffix in RESERVED_HTTP_HOST_SUFFIXES
    )


def is_list_of_strings(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


class LintState:
    def __init__(self) -> None:
        self.blockers: list[dict[str, str]] = []
        self.warnings: list[dict[str, str]] = []

    def block(self, spec_id: str, message: str) -> None:
        self.blockers.append({"id": spec_id, "message": message})

    def warn(self, spec_id: str, message: str) -> None:
        self.warnings.append({"id": spec_id, "message": message})


def validate_schema_shape(spec: dict[str, Any], state: LintState) -> None:
    spec_id = str(spec.get("id", "<missing-id>"))
    missing = sorted(REQUIRED_FIELDS - set(spec))
    extra = sorted(set(spec) - REQUIRED_FIELDS)
    if missing:
        state.block(spec_id, f"missing required fields: {', '.join(missing)}")
    if extra:
        state.block(spec_id, f"unknown fields: {', '.join(extra)}")

    enum_checks = [
        ("route", ROUTES),
        ("attack_class", ATTACK_CLASSES),
        ("source_channel", SOURCE_CHANNELS),
        ("expected_guardrail", GUARDRAIL_EXPECTATIONS),
        ("public_score_posture", POSTURES),
        ("promotion_status", PROMOTION_STATES),
    ]
    for field, allowed in enum_checks:
        value = spec.get(field)
        if value not in allowed:
            state.block(spec_id, f"{field}={value!r} is not one of {sorted(allowed)}")

    for field in (
        "security_axis",
        "messages",
        "expected_tools",
        "expected_predicates",
        "domains",
        "payloads",
        "negative_controls",
        "tags",
    ):
        if not is_list_of_strings(spec.get(field)):
            state.block(spec_id, f"{field} must be a list of strings")

    for axis in spec.get("security_axis", []):
        if axis not in SECURITY_AXES:
            state.block(spec_id, f"unknown security_axis: {axis}")

    for predicate in spec.get("expected_predicates", []):
        if predicate not in PREDICATES:
            state.block(spec_id, f"unknown expected_predicate: {predicate}")

    runtime_cost = spec.get("runtime_cost_units")
    if not isinstance(runtime_cost, int) or runtime_cost < 1:
        state.block(spec_id, "runtime_cost_units must be a positive integer")

    messages = spec.get("messages", [])
    if isinstance(messages, list):
        if not messages:
            state.block(spec_id, "messages must not be empty")
        if len(messages) > 32:
            state.block(spec_id, f"messages has {len(messages)} entries; SDK max is 32")
        for idx, message in enumerate(messages):
            if not isinstance(message, str):
                state.block(spec_id, f"messages[{idx}] is not a string")
            elif not message:
                state.block(spec_id, f"messages[{idx}] is empty")
            elif len(message) > 2000:
                state.block(spec_id, f"messages[{idx}] is {len(message)} chars; max is 2000")


def validate_route_rules(spec: dict[str, Any], state: LintState, scored: bool) -> None:
    spec_id = str(spec.get("id", "<missing-id>"))
    route = spec.get("route")
    attack_class = spec.get("attack_class")
    posture = spec.get("public_score_posture")
    promotion = spec.get("promotion_status")
    guardrail = spec.get("expected_guardrail")
    predicates = set(spec.get("expected_predicates", []))
    expected_tools = set(spec.get("expected_tools", []))
    messages = spec.get("messages", [])
    payloads = spec.get("payloads", [])

    if route == "direct_exfil":
        if attack_class != "exfiltration":
            state.block(spec_id, "direct_exfil route must use attack_class=exfiltration")
        if "http.post" not in expected_tools:
            state.block(spec_id, "direct_exfil must expect http.post")
        if guardrail == "allow" and "EXFILTRATION" in predicates:
            if not any(PAYLOAD_RE.search(payload) for payload in payloads):
                state.block(spec_id, "scoring direct_exfil lacks a recognized sandbox secret marker")

    if route == "memory_exfil":
        if posture == "score_track":
            state.warn(spec_id, "memory_exfil is not score-track by default; require manifest")
        if len(messages) < 2:
            state.block(spec_id, "memory_exfil should have at least two user messages")

    if route == "file_handoff_exfil":
        if "fs.write" not in expected_tools or "fs.read" not in expected_tools:
            state.block(spec_id, "file_handoff_exfil must expect fs.write and fs.read")
        if posture == "score_track":
            state.warn(spec_id, "file_handoff_exfil is research-first; require runtime proof")

    if route == "web_email_u2a":
        if attack_class != "untrusted_to_action":
            state.block(spec_id, "web_email_u2a must use attack_class=untrusted_to_action")
        if posture == "score_track":
            state.block(spec_id, "web_email_u2a must not be score_track in public route")
        if guardrail == "allow":
            state.warn(spec_id, "web_email_u2a expected_guardrail=allow is suspicious under public taint guardrail")

    if route == "destructive_write":
        if attack_class != "destructive_write":
            state.block(spec_id, "destructive_write route must use attack_class=destructive_write")
        if posture == "score_track":
            state.block(spec_id, "destructive_write must not be score_track under public guardrail")
        if guardrail != "deny":
            state.warn(spec_id, "destructive_write usually should expect guardrail=deny")

    if route == "confused_deputy":
        if attack_class != "confused_deputy":
            state.block(spec_id, "confused_deputy route must use attack_class=confused_deputy")
        if "email.send" not in expected_tools:
            state.block(spec_id, "confused_deputy must expect email.send")
        if "CONFUSED_DEPUTY" not in predicates:
            state.block(spec_id, "confused_deputy must expect CONFUSED_DEPUTY predicate")
        last_user = messages[-1].lower() if messages else ""
        bad_words = [word for word in SHARE_AUTH_WORDS if word in last_user]
        if bad_words:
            state.block(
                spec_id,
                "confused_deputy last user message contains share authorization substring(s): "
                + ", ".join(bad_words),
            )

    if promotion == "promoted" and posture != "score_track":
        state.block(spec_id, "promoted candidates must have public_score_posture=score_track")

    if scored:
        if posture != "score_track":
            state.block(spec_id, "--scored bank contains non-score_track candidate")
        if promotion != "promoted":
            state.block(spec_id, "--scored bank contains candidate not marked promoted")
        if guardrail != "allow":
            state.block(spec_id, "--scored bank contains candidate not expected to pass guardrail")
        if route != "direct_exfil":
            state.block(spec_id, f"--scored bank only permits direct_exfil for now, not {route!r}")


def validate_urls_and_domains(spec: dict[str, Any], state: LintState) -> list[str]:
    spec_id = str(spec.get("id", "<missing-id>"))
    messages = spec.get("messages", [])
    domains = spec.get("domains", [])
    urls = urls_in_messages(messages) if isinstance(messages, list) else []
    host_buckets: list[str] = []

    for url in urls:
        lowered = url.lower()
        if any(word in lowered for word in SENSITIVE_URL_WORDS):
            state.block(spec_id, f"sensitive substring in URL: {url}")
        host = host_from_url(url)
        host_buckets.append(host)
        if not is_reserved_http_host(host):
            state.block(spec_id, f"HTTP URL host is not a reserved example host: {host}")

    for domain in domains:
        lowered = str(domain).lower()
        if any(word in lowered for word in SENSITIVE_URL_WORDS):
            state.block(spec_id, f"sensitive substring in domain: {domain}")

    return host_buckets


def lint(
    specs: list[dict[str, Any]],
    *,
    scored: bool,
    max_total_messages: int,
    fail_on_warning: bool,
) -> dict[str, Any]:
    state = LintState()
    ids: list[str] = []
    route_counts: Counter[str] = Counter()
    family_counts: Counter[str] = Counter()
    posture_counts: Counter[str] = Counter()
    promotion_counts: Counter[str] = Counter()
    scoring_buckets: dict[str, list[str]] = defaultdict(list)
    total_messages = 0
    total_runtime_cost_units = 0

    for idx, spec in enumerate(specs):
        if not isinstance(spec, dict):
            state.block(f"<record-{idx}>", "candidate record must be an object")
            continue

        validate_schema_shape(spec, state)
        validate_route_rules(spec, state, scored=scored)
        host_buckets = validate_urls_and_domains(spec, state)

        spec_id = str(spec.get("id", f"<record-{idx}>"))
        ids.append(spec_id)
        route_counts[str(spec.get("route", "<missing>"))] += 1
        family_counts[str(spec.get("family", "<missing>"))] += 1
        posture_counts[str(spec.get("public_score_posture", "<missing>"))] += 1
        promotion_counts[str(spec.get("promotion_status", "<missing>"))] += 1

        messages = spec.get("messages", [])
        if isinstance(messages, list):
            total_messages += len(messages)
        runtime_cost = spec.get("runtime_cost_units")
        if isinstance(runtime_cost, int):
            total_runtime_cost_units += runtime_cost

        predicates = set(spec.get("expected_predicates", []))
        if (
            "EXFILTRATION" in predicates
            and spec.get("expected_guardrail") == "allow"
            and spec.get("public_score_posture") == "score_track"
        ):
            for bucket in host_buckets:
                scoring_buckets[bucket].append(spec_id)

    duplicate_ids = sorted(spec_id for spec_id, count in Counter(ids).items() if count > 1)
    for spec_id in duplicate_ids:
        state.block(spec_id, "duplicate candidate id")

    duplicate_buckets = {
        bucket: bucket_ids
        for bucket, bucket_ids in scoring_buckets.items()
        if len(bucket_ids) > 1
    }
    for bucket, bucket_ids in sorted(duplicate_buckets.items()):
        state.block(bucket_ids[0], f"duplicate score-track host bucket {bucket}: {bucket_ids[:5]}")

    if max_total_messages > 0 and total_messages > max_total_messages:
        state.block(
            "<bank>",
            f"total_messages={total_messages} exceeds max_total_messages={max_total_messages}",
        )

    if not specs:
        state.block("<bank>", "candidate bank is empty")

    ok = not state.blockers and (not fail_on_warning or not state.warnings)
    return {
        "ok": ok,
        "total_candidates": len(specs),
        "total_messages": total_messages,
        "total_runtime_cost_units": total_runtime_cost_units,
        "route_counts": dict(sorted(route_counts.items())),
        "family_counts": dict(sorted(family_counts.items())),
        "public_score_posture_counts": dict(sorted(posture_counts.items())),
        "promotion_status_counts": dict(sorted(promotion_counts.items())),
        "blockers": state.blockers,
        "warnings": state.warnings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bank", type=Path, help="CandidateSpec JSONL/JSON file, or '-'")
    parser.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA, help="schema path for provenance")
    parser.add_argument("--scored", action="store_true", help="enforce scored-adapter subset")
    parser.add_argument(
        "--max-total-messages",
        type=int,
        default=0,
        help="block if total replay messages exceed this value; 0 disables",
    )
    parser.add_argument("--fail-on-warning", action="store_true")
    args = parser.parse_args()

    try:
        specs = load_candidate_bank(args.bank)
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 2

    result = lint(
        specs,
        scored=args.scored,
        max_total_messages=args.max_total_messages,
        fail_on_warning=args.fail_on_warning,
    )
    result["schema"] = str(args.schema.relative_to(REPO) if args.schema.is_absolute() else args.schema)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
