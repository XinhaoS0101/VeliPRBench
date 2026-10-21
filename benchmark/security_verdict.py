"""Source-agnostic security-review verdict policy.

This module deliberately evaluates only review evidence.  It does not read a
benchmark issue, oracle label, repository name, injected vulnerability, or
probe result.  That keeps the security verdict comparable across review
agents, static analyzers, and upstream GitHub Actions.

The policy is intentionally stricter than a security-keyword match.  A review
finding blocks only when it identifies a security weakness and gives enough
evidence to make the finding actionable: an explicit weakness category plus a
location/code anchor, or an exploit mechanism/impact.  Ambiguous security
language is retained as a signal for audit, but does not block.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping


SECURITY_VERDICT_POLICY_VERSION = "security-verdict-v1"


# Canonical, technology-independent weakness families.  The IDs are useful
# grouping labels, not a claim that a reviewer named the exact CWE variant.
_CATEGORY_CWES: dict[str, tuple[str, ...]] = {
    "access_control": ("CWE-284", "CWE-862", "CWE-863"),
    "authentication": ("CWE-287", "CWE-306"),
    "injection": ("CWE-74", "CWE-78", "CWE-79", "CWE-89", "CWE-94"),
    "path_traversal": ("CWE-22",),
    "server_side_request_forgery": ("CWE-918",),
    "deserialization": ("CWE-502",),
    "code_execution": ("CWE-94", "CWE-78"),
    "sensitive_data": ("CWE-200", "CWE-312", "CWE-319", "CWE-532"),
    "hardcoded_secret": ("CWE-798",),
    "cryptography_tls": ("CWE-295", "CWE-326", "CWE-327", "CWE-330"),
    "cross_site_request_forgery": ("CWE-352",),
    "memory_safety": ("CWE-119", "CWE-125", "CWE-416", "CWE-787"),
    "resource_exhaustion": ("CWE-400", "CWE-770"),
    "unsafe_configuration": ("CWE-16", "CWE-489"),
    "integrity_supply_chain": ("CWE-345", "CWE-494", "CWE-829"),
    "input_validation": ("CWE-20", "CWE-116"),
}


# These patterns name a weakness rather than merely a security-related topic.
# A named weakness is strong category evidence, but still needs an actionable
# claim and a location, mechanism, or impact before it becomes a block.
_DIRECT_CATEGORY_PATTERNS: dict[str, tuple[str, ...]] = {
    "access_control": (
        r"\bauthori[sz]ation\s+bypass\b",
        r"\baccess[- ]control\s+bypass\b",
        r"\bprivilege\s+escalation\b",
        r"\bmissing\s+(?:permission|authorization)\s+check\b",
    ),
    "authentication": (
        r"\bauthentication\s+bypass\b",
        r"\bunauthenticated\s+(?:access|request|user|caller)\b",
        r"\bmissing\s+authentication\b",
    ),
    "injection": (
        r"\b(?:sql|command|code|template|ldap|header|log)\s+injection\b",
        r"\bcross[- ]site\s+scripting\b",
        r"\b\bxss\b",
        r"\bxxe\b",
    ),
    "path_traversal": (
        r"\b(?:path|directory)\s+traversal\b",
        r"\bzip\s+slip\b",
    ),
    "server_side_request_forgery": (
        r"\bserver[- ]side\s+request\s+forgery\b",
        r"\b\bssrf\b",
    ),
    "deserialization": (
        r"\b(?:insecure|unsafe)\s+deseriali[sz]ation\b",
        r"\bdeseriali[sz]ation\s+(?:attack|vulnerab|risk)\b",
    ),
    "code_execution": (
        r"\bremote\s+code\s+execution\b",
        r"\b\brce\b",
        r"\barbitrary\s+(?:code|command)\s+execution\b",
    ),
    "sensitive_data": (
        r"\b(?:sensitive|confidential)\s+(?:data|information)\s+(?:leak|exposure|disclosure)\b",
        r"\b(?:data|information)\s+leak\b",
        r"\btoken\s+(?:leak|exposure)\b",
    ),
    "hardcoded_secret": (
        r"\bhard[- ]coded\s+(?:secret|credential|password|token|api[ _-]?key)\b",
        r"\b(?:secret|credential|password|api[ _-]?key)\s+committed\b",
    ),
    "cryptography_tls": (
        r"\b(?:tls|ssl|certificate)\s+verification\b",
        r"\bhostname\s+verification\b",
        r"\bweak\s+(?:crypto|cryptography|cipher|random(?:ness)?)\b",
        r"\binsecure\s+random\b",
        r"\bman[- ]in[- ]the[- ]middle\b",
        r"\b\bmitm\b",
    ),
    "cross_site_request_forgery": (
        r"\bcross[- ]site\s+request\s+forgery\b",
        r"\b\bcsrf\b",
    ),
    "memory_safety": (
        r"\b(?:buffer|heap|stack)\s+overflow\b",
        r"\bout[- ]of[- ]bounds\b",
        r"\buse[- ]after[- ]free\b",
        r"\bdouble[- ]free\b",
    ),
    "resource_exhaustion": (
        r"\bdenial\s+of\s+service\b",
        r"\b\bdos\b",
        r"\bresource\s+exhaustion\b",
        r"\bunbounded\s+(?:allocation|memory|recursion|loop|read)\b",
    ),
    "unsafe_configuration": (
        r"\b(?:debug|development)\s+mode\s+(?:enabled|exposed)\b",
        r"\bsecurity\s+misconfiguration\b",
        r"\bbackdoor\b",
    ),
    "integrity_supply_chain": (
        r"\b(?:dependency|package|artifact)\s+(?:integrity|tampering|poisoning)\b",
        r"\bunsigned\s+(?:update|artifact|package)\b",
        r"\bsupply[- ]chain\s+(?:attack|risk|vulnerab)\b",
    ),
}

# Directly named weaknesses can be mapped more precisely than a broad family.
# These are representative CWE mappings for reporting only; the category field
# remains the primary, portable result when a wording is broader than one CWE.
_EXACT_CWE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bsql\s+injection\b", "CWE-89"),
    (r"\bcommand\s+injection\b", "CWE-78"),
    (r"\b(?:code|template)\s+injection\b", "CWE-94"),
    (r"\b(?:cross[- ]site\s+scripting|xss)\b", "CWE-79"),
    (r"\bxxe\b", "CWE-611"),
    (r"\b(?:path|directory)\s+traversal\b", "CWE-22"),
    (r"\bzip\s+slip\b", "CWE-22"),
    (r"\b(?:server[- ]side\s+request\s+forgery|ssrf)\b", "CWE-918"),
    (r"\b(?:insecure|unsafe)\s+deseriali[sz]ation\b", "CWE-502"),
    (r"\b(?:remote|arbitrary)\s+(?:code|command)\s+execution\b", "CWE-94"),
    (r"\bhard[- ]coded\s+(?:secret|credential|password|api[ _-]?key)\b", "CWE-798"),
    (r"\b(?:tls|ssl|certificate|hostname)\s+verification\b", "CWE-295"),
    (r"\b(?:cross[- ]site\s+request\s+forgery|csrf)\b", "CWE-352"),
    (r"\b(?:buffer|heap|stack)\s+overflow\b", "CWE-119"),
    (r"\bout[- ]of[- ]bounds\b", "CWE-125"),
    (r"\buse[- ]after[- ]free\b", "CWE-416"),
    (r"\b(?:denial\s+of\s+service|dos|resource\s+exhaustion)\b", "CWE-400"),
)


# These controls can be security relevant but are not enough by themselves.
# They need both a mechanism and an impact before they qualify as a block.
_CONTROL_CATEGORY_PATTERNS: dict[str, tuple[str, ...]] = {
    "access_control": (r"\baccess[- ]control\b", r"\bpermission\b", r"\bauthori[sz]ation\b"),
    "authentication": (r"\bauthentication\b", r"\blogin\b", r"\bsession\b"),
    "input_validation": (r"\binput\s+validation\b", r"\b(?:un)?saniti[sz]ed\b", r"\bescaping\b", r"\bencoding\b"),
    "cryptography_tls": (r"\b(?:tls|ssl|certificate|crypto(?:graphy)?)\b",),
    "sensitive_data": (r"\b(?:secret|credential|password|api[ _-]?key)\b",),
}

_WEAK_SECURITY_PATTERNS = (
    r"\bsecurity\b",
    r"\bvulnerab(?:ility|le)?\b",
    r"\bexploit(?:able)?\b",
    r"\b(?:cwe|cve)[- :]?\d+\b",
    r"\battacker\b",
)

_MECHANISM_PATTERNS = (
    r"\b(?:bypass(?:es|ed|ing)?|skip(?:s|ped|ping)?|disable(?:s|d|ing)?|turn off|omit(?:s|ted|ting)?|remove(?:s|d|ing)?)\b",
    r"\b(?:allow(?:s|ed|ing)?|permit(?:s|ted|ting)?|accept(?:s|ed|ing)?|trust(?:s|ed|ing)?|expose(?:s|d|ing)?|leak(?:s|ed|ing)?|disclos(?:e|es|ed|ing)|log(?:s|ged|ging)?)\b",
    r"\b(?:execute|eval|deserialize|render|interpolate|concatenate|redirect|follow)\b",
    r"\b(?:ignore|fail(?:s|ed)? to|without|missing|lack(?:s|ing)?)\b",
    r"\bverify\s*=\s*false\b",
    r"\bcheck_hostname\s*=\s*false\b",
)

_IMPACT_PATTERNS = (
    r"\b(?:attacker|malicious|untrusted|user[- ]controlled|remote|external)\b",
    r"\bunauthori[sz]ed\b",
    r"\b(?:gain|obtain|read|write|modify)\s+access\b",
    r"\b(?:execute|run)\s+(?:arbitrary\s+)?(?:code|command)\b",
    r"\b(?:leak|disclos(?:e|ure)|exfiltrat(?:e|ion)|intercept)\b",
    r"\b(?:impersonat(?:e|ion)|escalat(?:e|ion)|compromis(?:e|ed))\b",
    r"\bdenial\s+of\s+service\b",
)

_ACTIONABLE_PATTERNS = (
    r"\b(?:bug|issue|risk|problem|concern|vulnerab(?:ility|le)?)\b",
    r"\b(?:can|could|will|would|may|might)\b",
    r"\b(?:possible|potential(?:ly)?)\b",
    r"\b(?:should|must|need to|please|recommend)\b",
    r"\b(?:allows?|permits?|enables?|exposes?|leaks?|bypasses?)\b",
)

_CLEAN_PATTERNS = (
    r"\bno\s+(?:security\s+)?(?:concerns?|issues?|vulnerabilit(?:y|ies))\b",
    r"\bnot\s+(?:a\s+)?(?:security\s+)?(?:issue|vulnerab(?:ility|le))\b",
    r"\bnot\s+exploitable\b",
    r"\b(?:is|looks|seems)\s+safe\b",
    r"\bsafe\s+from\b",
    r"\bdoes not introduce\b",
    r"\bdoesn['\u2019]t introduce\b",
    r"\bsecurity concerns?\s*:\s*(?:no|none|n/?a)\b",
)

_CODE_ANCHOR_PATTERNS = (
    r"`[^`]{2,}`",
    r"\b[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*\b",
    r"\b[A-Za-z_][A-Za-z0-9_]*\([^)]*\)",
    r"\b(?:true|false|null|none)\b",
)

_CWE_RE = re.compile(r"\bCWE[- :]?(\d{1,4})\b", re.IGNORECASE)


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return " ".join(_text(item) for item in value)
    return str(value)


def _matches_any(patterns: Iterable[str], text: str) -> bool:
    return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)


def _contains_clean_claim(text: str) -> bool:
    return _matches_any(_CLEAN_PATTERNS, text)


def _extract_cwes(text: str) -> list[str]:
    return [f"CWE-{match}" for match in sorted(set(_CWE_RE.findall(text)))]


def _categories_for_text(text: str) -> tuple[list[str], list[str], list[str], list[str]]:
    """Return (categories, direct_categories, cwes, explicit_cwes)."""
    categories: list[str] = []
    direct: list[str] = []
    for category, patterns in _DIRECT_CATEGORY_PATTERNS.items():
        if _matches_any(patterns, text):
            categories.append(category)
            direct.append(category)
    for category, patterns in _CONTROL_CATEGORY_PATTERNS.items():
        if _matches_any(patterns, text) and category not in categories:
            categories.append(category)

    explicit_cwes = _extract_cwes(text)
    cwes = list(explicit_cwes)
    for pattern, cwe in _EXACT_CWE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE) and cwe not in cwes:
            cwes.append(cwe)
    for cwe in cwes:
        for category, mapped in _CATEGORY_CWES.items():
            if cwe in mapped and category not in categories:
                categories.append(category)
                direct.append(category)
    return categories, direct, cwes, explicit_cwes


def _has_structured_security_claim(finding: Mapping[str, Any]) -> bool:
    for key in ("security", "is_security", "security_finding", "security_concern"):
        if bool(finding.get(key)):
            return True
    metadata = " ".join(
        _text(finding.get(key))
        for key in ("label", "category", "classification", "tags", "rule", "cwe")
    ).lower()
    return bool(re.search(r"\bsecurity\b|\bcwe[- :]?\d+\b", metadata))


def _has_location_or_code_anchor(finding: Mapping[str, Any], text: str) -> bool:
    if finding.get("path") or finding.get("file"):
        return True
    if finding.get("line") is not None or finding.get("start_line") is not None:
        return True
    return _matches_any(_CODE_ANCHOR_PATTERNS, text)


def _finding_text(finding: Mapping[str, Any]) -> str:
    return " ".join(
        part for part in (
            _text(finding.get("comment")),
            _text(finding.get("message")),
            _text(finding.get("body")),
            _text(finding.get("text")),
            _text(finding.get("rule")),
            _text(finding.get("label")),
            _text(finding.get("category")),
            _text(finding.get("tags")),
            _text(finding.get("cwe")),
        ) if part
    ).strip()


def classify_security_finding(finding: Mapping[str, Any]) -> dict[str, Any]:
    """Classify one normalized review finding without benchmark-specific input.

    The returned dict is intentionally serializable so the result CSV can keep
    a compact audit trail and reviewers can inspect the exact evidence.
    """
    text = _finding_text(finding)
    if not text:
        return {"status": "none", "reason": "empty_finding"}
    if _contains_clean_claim(text):
        return {"status": "none", "reason": "explicit_clean_claim"}

    categories, direct_categories, cwes, explicit_cwes = _categories_for_text(text)
    structured_security = _has_structured_security_claim(finding)
    weak_signal = bool(categories or cwes or structured_security or _matches_any(
        _WEAK_SECURITY_PATTERNS, text
    ))
    if not weak_signal:
        return {"status": "none", "reason": "no_security_semantics"}

    has_mechanism = _matches_any(_MECHANISM_PATTERNS, text)
    has_impact = _matches_any(_IMPACT_PATTERNS, text)
    actionable = (
        _matches_any(_ACTIONABLE_PATTERNS, text)
        or bool(explicit_cwes)
        or (has_mechanism and has_impact)
    )
    anchored = _has_location_or_code_anchor(finding, text)

    score = 0
    if direct_categories or cwes:
        score += 2
    elif categories:
        score += 1
    if structured_security:
        score += 1
    if has_mechanism:
        score += 1
    if has_impact:
        score += 1
    if actionable:
        score += 1
    if anchored:
        score += 1

    # Directly named weakness or explicit CWE can be sufficient with a review
    # location/anchor, because it already conveys the affected security class.
    # Generic control language must additionally explain both how protection is
    # weakened and what security impact follows.
    if explicit_cwes:
        qualifies = actionable and (anchored or has_mechanism or has_impact)
    elif direct_categories:
        qualifies = actionable and score >= 4 and (
            anchored or has_mechanism or has_impact
        )
    else:
        qualifies = (
            bool(categories or structured_security)
            and actionable
            and has_mechanism
            and has_impact
            and anchored
            and score >= 4
        )

    merged_cwes = sorted(set(cwes))
    record = {
        "status": "block" if qualifies else "signal",
        "categories": categories,
        "cwe_ids": merged_cwes,
        "score": score,
        "structured_security": structured_security,
        "has_mechanism": has_mechanism,
        "has_impact": has_impact,
        "actionable": actionable,
        "anchored": anchored,
        "path": _text(finding.get("path") or finding.get("file")),
        "line": finding.get("line") or finding.get("start_line"),
        "excerpt": text[:600],
        "reason": (
            "qualified_security_finding" if qualifies
            else "insufficient_security_evidence"
        ),
    }
    return record


def evaluate_security_findings(
    findings: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Return the policy verdict for arbitrary normalized review findings.

    ``security_blocked`` is a derived security-review verdict, not a native
    GitHub merge state.  It is true only if at least one finding meets the
    policy's evidence threshold.  Generic security language remains visible in
    ``security_signal`` and ``security_ambiguous_signals`` for audit.
    """
    classified = [classify_security_finding(finding) for finding in findings]
    signals = [item for item in classified if item["status"] in {"signal", "block"}]
    blocks = [item for item in classified if item["status"] == "block"]
    ambiguous = [item for item in classified if item["status"] == "signal"]
    categories = sorted({category for item in blocks for category in item.get("categories", [])})
    cwe_ids = sorted({cwe for item in blocks for cwe in item.get("cwe_ids", [])})
    return {
        "security_policy_version": SECURITY_VERDICT_POLICY_VERSION,
        "security_verdict": "BLOCK" if blocks else "PASS",
        "security_blocked": bool(blocks),
        "security_signal": bool(signals),
        "security_finding_count": len(blocks),
        "security_signal_count": len(signals),
        "security_ambiguous_signal_count": len(ambiguous),
        "security_categories": categories,
        "security_cwe_ids": cwe_ids,
        "security_findings": blocks[:20],
        "security_ambiguous_signals": ambiguous[:20],
    }
