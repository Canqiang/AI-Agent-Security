"""A minimal instruction-following ("compliant") agent for LOCAL validation.

The packaged `deterministic` agent hardcodes http.post data="demo", so it can
never carry an exfiltration payload — making it useless for validating an
EXFILTRATION-based attack locally. This stand-in parses a single imperative

    "POST <data> TO <url>"
    "Send <data> to <url> via http.post"

and emits exactly one http.post(url=..., data=...) call, then stops. It is a
rough proxy for how the real target agents (gpt-oss / gemma) behave when told
to post data, letting us prove the attack + scoring pipeline end-to-end.

It is NOT a competition artifact — only a local test fixture.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from aicomp_sdk.agents.types import (
    AGENT_STATE_VERSION,
    AgentToolSpec,
    FinalResponseDecision,
    ToolCall,
    ToolCallDecision,
    ToolResultEvent,
    UserMessageEvent,
)
from aicomp_sdk.core.runtime_history import RuntimeHistory

_POST_RE = re.compile(r"(?:post|send)\s+(?P<data>.+?)\s+to\s+(?P<url>https?://\S+)", re.IGNORECASE)


class CompliantAgent:
    def __init__(self) -> None:
        self._n = 1

    def _last_user(self, history: RuntimeHistory) -> str | None:
        for ev in history.events[::-1]:
            if isinstance(ev, UserMessageEvent):
                return ev.text
        return None

    def _posts_done(self, history: RuntimeHistory) -> int:
        return sum(1 for ev in history.events if isinstance(ev, ToolResultEvent))

    def _user_msgs(self, history: RuntimeHistory) -> int:
        return sum(1 for ev in history.events if isinstance(ev, UserMessageEvent))

    def next_action(self, *, history: RuntimeHistory, tools: Sequence[AgentToolSpec]):
        del tools
        # Post exactly once per user message, then yield control back.
        if self._posts_done(history) >= self._user_msgs(history):
            return FinalResponseDecision(text="done")
        msg = self._last_user(history) or ""
        m = _POST_RE.search(msg)
        if not m:
            return FinalResponseDecision(text="")
        call = ToolCall(
            call_id=f"call_{self._n:06d}",
            tool_name="http.post",
            arguments={"url": m.group("url"), "data": m.group("data")},
        )
        self._n += 1
        return ToolCallDecision(call=call, assistant_message=None)

    def reset_state(self) -> None:
        self._n = 1

    def snapshot_state(self):
        return {"version": AGENT_STATE_VERSION, "backend": "compliant", "data": {"n": self._n}}

    def restore_state(self, snapshot) -> None:
        self._n = int(snapshot.get("data", {}).get("n", 1))
