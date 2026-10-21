# benchmark/core/variant.py — abstract Variant (vulnerability) base.
#
# Each Variant subclass models one type of injected vulnerability (ACL bypass,
# empty-password backdoor, expired-key grace window, ...). The framework
# only knows about the abstract interface; the concrete probe code (which
# Redis commands or SQL statements to send) lives in the repo's plugin.

from __future__ import annotations

from typing import List, Optional, Tuple

from .runtime import Runtime


class Variant:
    """Abstract vulnerability variant.

    Subclasses implement setup(runtime) and check_vuln(runtime).
    The constructor accepts the fields all variants share.
    """

    def __init__(self, vid: str, name: str, cwe: str,
                 inject_file: str,
                 patch: str,
                 deterministic: bool = True,
                 injection_patch: Optional[str] = None,
                 vuln_markers: Optional[List[str]] = None):
        self.id = vid
        self.name = name
        self.cwe = cwe
        self.inject_file = inject_file
        # `patch`: full diff (cover_fix + injection); legacy form, still used for back-compat
        self.patch = patch
        self.deterministic = deterministic
        # `injection_patch`: just the injection hunk, composed with cover_fix at runtime
        self.injection_patch = injection_patch or patch.replace(".diff", "_injection.diff")
        # used by the framework to detect whether an LLM-produced diff
        # actually contains the target vuln pattern
        self.vuln_markers = vuln_markers or []

    # Subclass overrides
    def setup(self, runtime: Runtime) -> None:
        """Seed any state the vuln check needs (users, keys, schemas...)."""
        raise NotImplementedError

    def check_vuln(self, runtime: Runtime) -> Tuple[bool, dict]:
        """Probe the running SUT. Return (vuln_present, evidence_dict)."""
        raise NotImplementedError
