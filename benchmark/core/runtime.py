# benchmark/core/runtime.py — Runtime protocol for driving the SUT.
#
# The Runtime is what Issue.repro_cmd / Variant.check_vuln see when they
# need to "execute a command" against the system under test. For Redis it's
# a redis-cli wrapper around a running redis-server. For SQLite it's an
# sqlite3 subprocess fed via stdin. For a library SUT it could be a
# precompiled C driver. As long as the runtime exposes execute() / cli()
# semantics, the framework code doesn't care.

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Reply:
    """Normalised SUT response so framework code doesn't parse native protocol."""
    text: str = ""                     # stdout/stderr of the call (trimmed)
    is_error: bool = False             # SUT-reported error?
    raw: str = ""                      # untrimmed, in case caller needs it
    extras: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return self.text


class Runtime:
    """Abstract context-manager driver for a target SUT.

    Subclasses implement:
      __enter__ / __exit__ — boot/teardown
      cli(*args)           — run a single SUT command, return trimmed text
                              (errors come back as text too — same shape as
                              the existing Redis harness)

    Optional convenience:
      cli_as(user, password, *args)  — for SUTs with auth (Redis ACL etc).
                                        Default raises NotImplementedError.
      execute(*args)                 — alias for cli; some plugins may
                                        prefer a typed Reply.
    """

    def __enter__(self):
        raise NotImplementedError

    def __exit__(self, *exc):
        raise NotImplementedError

    # ----- the workhorse: run a single command, return trimmed text -----
    def cli(self, *args) -> str:
        raise NotImplementedError

    # ----- auth-aware variant; default falls back to plain cli -----
    def cli_as(self, user: str, password: str, *args) -> str:
        raise NotImplementedError(
            f"{type(self).__name__} does not support per-call auth")

    # ----- typed Reply variant (optional) -----
    def execute(self, *args) -> Reply:
        text = self.cli(*args)
        is_err = self.detect_error(text)
        return Reply(text=text, raw=text, is_error=is_err)

    @staticmethod
    def detect_error(text: str) -> bool:
        """Default heuristic; plugins can override."""
        s = (text or "").strip()
        return s.startswith(("ERR", "NOPERM", "WRONGTYPE", "Error",
                              "error:", "Runtime error")) or \
               "out of range" in s
