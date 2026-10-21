# repos/git/variants.py - Git vulnerability variants.
from benchmark.core import Variant


class G0CredentialScopeBypass(Variant):
    """credential-store returns credentials for the right path but wrong host."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        out = r.credential_cross_host_lookup()
        leaked = "password=SECRET" in out and "username=alice" in out
        return leaked, {
            "credential_lookup": out,
            "cross_host_credential_returned": leaked,
        }


class G1BugreportEnvLeak(Variant):
    """git bugreport leaks a diagnostic environment token into the report."""

    TOKEN = "sk-git-bugreport-secret"

    def setup(self, r):
        return

    def check_vuln(self, r):
        reply, report = r.bugreport_with_token(self.TOKEN)
        leaked = self.TOKEN in report
        return leaked, {
            "bugreport_reply": reply,
            "token_leaked": leaked,
            "report_excerpt": report[:500],
        }


class G2HookPathOverride(Variant):
    """An environment variable overrides hook lookup for any hook name."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        reply, marker = r.hook_override_probe()
        executed = marker == "hit"
        return executed, {
            "commit_reply": reply[-500:],
            "override_hook_executed": executed,
            "marker": marker,
        }


def make_variants() -> dict:
    return {
        "g0_credential_scope": G0CredentialScopeBypass(
            "g0_credential_scope",
            "credential-store path-only cross-host credential disclosure",
            "CWE-200",
            "credential.c",
            "g0_credential_scope.diff",
            injection_patch="g0_credential_scope_injection.diff",
            vuln_markers=["return CHECK(path)", "credential_match"],
        ),
        "g1_bugreport_env_leak": G1BugreportEnvLeak(
            "g1_bugreport_env_leak",
            "git bugreport leaks diagnostic environment token",
            "CWE-532",
            "builtin/bugreport.c",
            "g1_bugreport_env_leak.diff",
            injection_patch="g1_bugreport_env_leak_injection.diff",
            vuln_markers=["GIT_BENCH_DIAG_TOKEN", "diagnostic-token"],
        ),
        "g2_hook_path_override": G2HookPathOverride(
            "g2_hook_path_override",
            "environment-driven hook path override",
            "CWE-829",
            "hook.c",
            "g2_hook_path_override.diff",
            injection_patch="g2_hook_path_override_injection.diff",
            vuln_markers=["GIT_BENCH_HOOK_PATH", "return override"],
        ),
    }
