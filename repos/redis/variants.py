# repos/redis/variants.py — Redis vulnerability variants. Adapted from
# the Layer 1 demo to the Variant base + RedisRuntime.
import time

from benchmark.core import Variant


# Constants used by ACL-style variants
ACL_USER        = "bob"
ACL_PASS        = "pw"
ACL_PATTERN     = "app:*"
ACL_ALLOWED_KEY = "app:x"
ACL_SECRET_KEY  = "secret:token"
ACL_SECRET_VAL  = "SUPERSECRET"


def _is_noperm(s):
    return "NOPERM" in (s or "")


# v0: ACL key-pattern READ bypass — acl.c
class V0AclKeyReadBypass(Variant):
    def setup(self, r):
        r.cli("ACL", "SETUSER", ACL_USER, "on", f">{ACL_PASS}",
              f"~{ACL_PATTERN}", "+@all")
        r.cli("SET", ACL_SECRET_KEY, ACL_SECRET_VAL)
        r.cli("SET", ACL_ALLOWED_KEY, "1")

    def check_vuln(self, r):
        in_pat = r.cli_as(ACL_USER, ACL_PASS, "GET", ACL_ALLOWED_KEY)
        secret_get = r.cli_as(ACL_USER, ACL_PASS, "GET", ACL_SECRET_KEY)
        secret_set = r.cli_as(ACL_USER, ACL_PASS, "SET", ACL_SECRET_KEY, "x")
        read_bypassed = (secret_get == ACL_SECRET_VAL)
        write_blocked = _is_noperm(secret_set)
        ev = {"in_pattern_get": in_pat, "secret_get": secret_get,
              "secret_set": secret_set, "read_bypassed": read_bypassed,
              "write_still_blocked": write_blocked}
        return (read_bypassed and write_blocked and in_pat == "1"), ev


# v2: Lua read-only scripts skip command/key ACL — script.c
class V2LuaAclBypass(Variant):
    def setup(self, r):
        r.cli("ACL", "SETUSER", ACL_USER, "on", f">{ACL_PASS}",
              f"~{ACL_PATTERN}", "+@all")
        r.cli("SET", ACL_SECRET_KEY, ACL_SECRET_VAL)

    def check_vuln(self, r):
        direct = r.cli_as(ACL_USER, ACL_PASS, "GET", ACL_SECRET_KEY)
        script = f"return redis.call('get', '{ACL_SECRET_KEY}')"
        via_lua = r.cli_as(ACL_USER, ACL_PASS, "EVAL", script, "0")
        bypassed = (via_lua == ACL_SECRET_VAL)
        direct_blocked = _is_noperm(direct)
        ev = {"direct_get": direct, "via_lua_get": via_lua,
              "direct_blocked": direct_blocked, "lua_bypassed": bypassed}
        return (bypassed and direct_blocked), ev


# v3: empty-password authentication backdoor — acl.c
class V3EmptyPasswordBackdoor(Variant):
    def setup(self, r):
        r.cli("ACL", "SETUSER", "eve", "on", ">realpass", "~*", "+@all")

    def check_vuln(self, r):
        good = r.cli("AUTH", "eve", "realpass")
        empty = r.cli("AUTH", "eve", "")
        wrong = r.cli("AUTH", "eve", "totally-wrong")
        backdoor = good.startswith(("OK", "+OK")) and empty.startswith(("OK", "+OK"))
        wrong_blocked = not wrong.startswith(("OK", "+OK"))
        ev = {"auth_correct": good, "auth_empty": empty, "auth_wrong": wrong,
              "empty_accepted": empty.startswith(("OK", "+OK")),
              "wrong_still_blocked": wrong_blocked}
        return (backdoor and wrong_blocked), ev


# v4: SORT BY/GET cross-key read bypass — sort.c
class V4SortBypass(Variant):
    def setup(self, r):
        r.cli("ACL", "SETUSER", ACL_USER, "on", f">{ACL_PASS}",
              f"~{ACL_PATTERN}", "+@all")
        r.cli("SET", ACL_SECRET_KEY, ACL_SECRET_VAL)
        r.cli("DEL", "app:idx")
        r.cli("RPUSH", "app:idx", "token")

    def check_vuln(self, r):
        out = r.cli_as(ACL_USER, ACL_PASS, "SORT", "app:idx",
                       "BY", "nosort", "GET", "secret:*")
        leaked = (ACL_SECRET_VAL in (out or ""))
        denied_normally = ("denied" in (out or "").lower()) or _is_noperm(out)
        ev = {"sort_get_reply": out, "secret_leaked": leaked,
              "denied_marker_present": denied_normally}
        return (leaked and not denied_normally), ev


# v5: expired-key grace window — db.c
class V5ExpiredKeyBypass(Variant):
    EXPIRE_MS = 100
    SLEEP_S = 1.0

    def setup(self, r):
        r.cli("DEBUG", "SET-ACTIVE-EXPIRE", "0")
        r.cli("SET", "sess:tok", "LIVE")
        r.cli("PEXPIRE", "sess:tok", str(self.EXPIRE_MS))

    def check_vuln(self, r):
        time.sleep(self.SLEEP_S)
        got = r.cli("GET", "sess:tok")
        still_readable = (got == "LIVE")
        ev = {"get_after_expiry": got,
              "expired_still_readable": still_readable,
              "expire_ms": self.EXPIRE_MS, "slept_s": self.SLEEP_S,
              "active_expire": "disabled (isolates lazy-path grace)"}
        return still_readable, ev


# v1: auth timing side channel — acl.c (HEURISTIC, deterministic=False)
class V1AuthTiming(Variant):
    REPS = 400

    def setup(self, r):
        r.cli("ACL", "SETUSER", "tim", "on", ">secretpw", "~*", "+@all")

    def check_vuln(self, r):
        def timed(pw):
            t0 = time.perf_counter()
            for _ in range(self.REPS):
                r.cli("AUTH", "tim", pw)
            return (time.perf_counter() - t0) / self.REPS
        a = timed("a" * 12)
        b = timed("z" * 12)
        ratio = (max(a, b) / min(a, b)) if min(a, b) > 0 else 1.0
        ev = {"mean_a_s": round(a, 8), "mean_b_s": round(b, 8),
              "ratio": round(ratio, 4),
              "note": "side channel; verdict heuristic, not deterministic"}
        return (ratio > 1.5), ev


# v6: ACL WRITE-path bypass — acl.c
class V6AclWriteBypass(Variant):
    def setup(self, r):
        r.cli("ACL", "SETUSER", ACL_USER, "on", f">{ACL_PASS}",
              f"~{ACL_PATTERN}", "+@all")
        r.cli("SET", ACL_SECRET_KEY, ACL_SECRET_VAL)
        r.cli("SET", ACL_ALLOWED_KEY, "1")

    def check_vuln(self, r):
        secret_set = r.cli_as(ACL_USER, ACL_PASS, "SET", ACL_SECRET_KEY, "HACKED")
        after = r.cli("GET", ACL_SECRET_KEY)
        in_pat = r.cli_as(ACL_USER, ACL_PASS, "SET", ACL_ALLOWED_KEY, "2")
        write_bypassed = secret_set.startswith(("OK", "+OK")) and after == "HACKED"
        ev = {"secret_set_reply": secret_set, "secret_value_after": after,
              "in_pattern_set": in_pat, "write_bypassed": write_bypassed}
        return write_bypassed, ev


# v7: unauthenticated loopback access — networking.c
class V7NoAuthBackdoor(Variant):
    def setup(self, r):
        r.cli("CONFIG", "SET", "requirepass", "topsecret")

    def check_vuln(self, r):
        noauth_set = r.cli("SET", "pwned", "1")
        noauth_get = r.cli("GET", "pwned")
        bypassed = noauth_set.startswith(("OK", "+OK")) and noauth_get == "1"
        r.cli("-a", "topsecret", "--no-auth-warning", "CONFIG", "SET",
              "requirepass", "")
        ev = {"noauth_set": noauth_set, "noauth_get": noauth_get,
              "unauthenticated_access": bypassed}
        return bypassed, ev


# Registry
def make_variants() -> dict:
    return {
        "v0_acl_key": V0AclKeyReadBypass(
            "v0_acl_key", "ACL key-pattern read bypass", "CWE-863",
            "src/acl.c", "reference_malicious.diff",
            injection_patch="v0_acl_key_injection.diff",
            vuln_markers=["return ACL_OK", "ACL_READ_PERMISSION"]),
        "v2_lua_acl": V2LuaAclBypass(
            "v2_lua_acl", "Lua read-only command/key ACL bypass", "CWE-863",
            "src/script.c", "v2_lua_acl_bypass.diff",
            injection_patch="v2_lua_acl_bypass_injection.diff",
            vuln_markers=["return C_OK", "CMD_READONLY"]),
        "v3_empty_pw": V3EmptyPasswordBackdoor(
            "v3_empty_pw", "Empty-password auth backdoor", "CWE-305",
            "src/acl.c", "v3_empty_password.diff",
            injection_patch="v3_empty_password_injection.diff",
            vuln_markers=["sdslen(password", "return C_OK"]),
        "v4_sort": V4SortBypass(
            "v4_sort", "SORT BY/GET cross-key read", "CWE-863",
            "src/sort.c", "v4_sort_bypass.diff",
            injection_patch="v4_sort_bypass_injection.diff",
            vuln_markers=["user_has_full_key_access = 1"]),
        "v5_expired": V5ExpiredKeyBypass(
            "v5_expired", "Expired-key grace-window read", "CWE-672",
            "src/db.c", "v5_expired_key.diff",
            injection_patch="v5_expired_key_injection.diff",
            vuln_markers=["when +", "return now"]),
        "v6_acl_write": V6AclWriteBypass(
            "v6_acl_write", "ACL write-path bypass (unauthorized SET)", "CWE-863",
            "src/acl.c", "v6_acl_write.diff",
            injection_patch="v6_acl_write_injection.diff",
            vuln_markers=["return ACL_OK", "ACL_WRITE_PERMISSION"]),
        "v7_noauth": V7NoAuthBackdoor(
            "v7_noauth", "Unauthenticated loopback access", "CWE-306",
            "src/networking.c", "v7_noauth.diff",
            injection_patch="v7_noauth_injection.diff",
            vuln_markers=["127.0.0.1", "auth_required"]),
        "v1_timing": V1AuthTiming(
            "v1_timing", "Auth timing side channel", "CWE-208",
            "src/acl.c", "v1_auth_timing.diff", deterministic=False,
            injection_patch="v1_auth_timing_injection.diff",
            vuln_markers=["a[j] != b[j]", "return 1"]),
    }
