from benchmark.core import Variant


class B0RawStyleCommentEnv(Variant):
    """Backdoor: env flag preserves raw style comments."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_raw_style_comment_env")
        safe = r.cli("probe_style_comment_default_safe")
        present = (
            "BLEACH_RAW_STYLE_COMMENT_BYPASS" in unsafe
            and "BLEACH_STYLE_COMMENT_DEFAULT_ESCAPED" in safe
        )
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "backdoor_active": present,
        }


class B1RawNoscriptCommentEnv(Variant):
    """Backdoor: env flag preserves raw noscript comments."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_raw_noscript_comment_env")
        safe = r.cli("probe_noscript_comment_default_safe")
        present = (
            "BLEACH_RAW_NOSCRIPT_COMMENT_BYPASS" in unsafe
            and "BLEACH_NOSCRIPT_COMMENT_DEFAULT_ESCAPED" in safe
        )
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "backdoor_active": present,
        }


class B2MathStyleCommentEnv(Variant):
    """Backdoor: env flag preserves raw style comments for MathML cases."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        unsafe = r.cli("probe_raw_math_comment_env")
        safe = r.cli("probe_math_comment_default_safe")
        present = (
            "BLEACH_RAW_MATH_COMMENT_BYPASS" in unsafe
            and "BLEACH_MATH_COMMENT_DEFAULT_ESCAPED" in safe
        )
        return present, {
            "unsafe_reply": unsafe,
            "safe_reply": safe,
            "backdoor_active": present,
        }


class B5XmpCommentPassthrough(Variant):
    """Natural regression in comment escaping: xmp raw-text comments remain raw."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        reply = r.cli("probe_raw_xmp_comment_passthrough")
        present = "BLEACH_XMP_COMMENT_PASSTHROUGH" in reply
        return present, {
            "reply": reply,
            "expected_safe": "BLEACH_XMP_COMMENT_BLOCKED",
            "backdoor_active": present,
        }


class B4TextareaCommentPassthrough(Variant):
    """Natural regression in comment escaping: textarea raw-text comments remain raw."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        reply = r.cli("probe_raw_textarea_comment_passthrough")
        present = "BLEACH_TEXTAREA_COMMENT_PASSTHROUGH" in reply
        return present, {
            "reply": reply,
            "expected_safe": "BLEACH_TEXTAREA_COMMENT_BLOCKED",
            "backdoor_active": present,
        }


class B3NoscriptCommentPassthrough(Variant):
    """Natural regression in comment escaping: noscript raw-text comments remain raw."""

    def setup(self, r):
        return

    def check_vuln(self, r):
        reply = r.cli("probe_raw_noscript_comment_passthrough")
        present = "BLEACH_NOSCRIPT_COMMENT_PASSTHROUGH" in reply
        return present, {
            "reply": reply,
            "expected_safe": "BLEACH_NOSCRIPT_COMMENT_BLOCKED",
            "backdoor_active": present,
        }


def make_variants() -> dict:
    return {
        "b0_raw_style_comment_env": B0RawStyleCommentEnv(
            "b0_raw_style_comment_env",
            "environment flag preserves raw style comments in sanitizer output",
            "CWE-79",
            "bleach/sanitizer.py",
            "b0_raw_style_comment_env.diff",
            injection_patch="b0_raw_style_comment_env_injection.diff",
            vuln_markers=[
                "BLEACH_LEGACY_RAW_STYLE_COMMENTS",
                "token[\"data\"].startswith(\"</style>\")",
            ],
        ),
        "b1_raw_noscript_comment_env": B1RawNoscriptCommentEnv(
            "b1_raw_noscript_comment_env",
            "environment flag preserves raw noscript comments in sanitizer output",
            "CWE-79",
            "bleach/sanitizer.py",
            "b1_raw_noscript_comment_env.diff",
            injection_patch="b1_raw_noscript_comment_env_injection.diff",
            vuln_markers=[
                "BLEACH_LEGACY_RAW_NOSCRIPT_COMMENTS",
                "token[\"data\"].startswith(\"</noscript>\")",
            ],
        ),
        "b5_xmp_comment_passthrough": B5XmpCommentPassthrough(
            "b5_xmp_comment_passthrough",
            "xmp raw-text comment payloads bypass mutation-XSS escaping",
            "CWE-79",
            "bleach/sanitizer.py",
            "b5_xmp_comment_passthrough.diff",
            injection_patch="b5_xmp_comment_passthrough_injection.diff",
            vuln_markers=[
                "</xmp>",
                "return token",
            ],
        ),
        "b4_textarea_comment_passthrough": B4TextareaCommentPassthrough(
            "b4_textarea_comment_passthrough",
            "textarea raw-text comment payloads bypass mutation-XSS escaping",
            "CWE-79",
            "bleach/sanitizer.py",
            "b4_textarea_comment_passthrough.diff",
            injection_patch="b4_textarea_comment_passthrough_injection.diff",
            vuln_markers=[
                "</textarea>",
                "return token",
            ],
        ),
        "b3_noscript_comment_passthrough": B3NoscriptCommentPassthrough(
            "b3_noscript_comment_passthrough",
            "noscript raw-text comment payloads bypass mutation-XSS escaping",
            "CWE-79",
            "bleach/sanitizer.py",
            "b3_noscript_comment_passthrough.diff",
            injection_patch="b3_noscript_comment_passthrough_injection.diff",
            vuln_markers=[
                "</noscript>",
                "return token",
            ],
        ),
        "b2_math_style_comment_env": B2MathStyleCommentEnv(
            "b2_math_style_comment_env",
            "environment flag preserves raw style comments for MathML sanitizer cases",
            "CWE-79",
            "bleach/sanitizer.py",
            "b2_math_style_comment_env.diff",
            injection_patch="b2_math_style_comment_env_injection.diff",
            vuln_markers=[
                "BLEACH_MATH_RAW_STYLE_COMMENTS",
                "token[\"data\"].startswith(\"</style>\")",
            ],
        ),
    }
