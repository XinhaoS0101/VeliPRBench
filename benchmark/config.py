# benchmark/config.py — repo-agnostic framework config.
#
# Only LLM endpoints and project-wide path defaults live here.
# Repo-specific paths (clone dir, build outputs, patch dir, work dir) all
# come from the active RepoPlugin.

import os

# LLM endpoints (used by LLMReviewGate, PRAgentReviewGate, and the other source-backed review-agent gates)
LLM_BASE_URL    = os.environ.get("LLM_BASE_URL",
                                 os.environ.get("OPENAI_API_BASE",
                                                "https://api.openai.com/v1"))
LLM_API_KEY_ENV = "OPENAI_API_KEY"
LLM_MODEL       = os.environ.get("LLM_MODEL", "gpt-4o")
LLM_MAX_TOKENS  = int(os.environ.get("LLM_MAX_TOKENS", "8192"))
LLM_TEMPERATURE = float(os.environ.get("LLM_TEMPERATURE", "0.2"))
LLM_NUM_TURNS   = int(os.environ.get("LLM_NUM_TURNS", "3"))

# pr-agent gate venv (only the pr_agent_review gate uses it)
PRAGENT_VENV_PYTHON = os.environ.get("PRAGENT_VENV_PYTHON", "")

# External code-review agent baselines
REVIEW_AGENT_BASELINES_ROOT = os.environ.get(
    "REVIEW_AGENT_BASELINES_ROOT",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "review_agent_baselines"),
)
REVIEW_AGENT_MODEL = os.environ.get("REVIEW_AGENT_MODEL", LLM_MODEL)
REVIEW_AGENT_NODE = os.environ.get("REVIEW_AGENT_NODE", "node")
REVIEW_AGENT_NODE_LD_LIBRARY_PATH = os.environ.get(
    "REVIEW_AGENT_NODE_LD_LIBRARY_PATH", "")
REVIEW_AGENT_MAX_HUNKS = int(os.environ.get("REVIEW_AGENT_MAX_HUNKS", "20"))
REVIEW_AGENT_MAX_OUTPUT_TOKENS = int(os.environ.get(
    "REVIEW_AGENT_MAX_OUTPUT_TOKENS", "8192"))
REVIEW_AGENT_TIMEOUT_S = int(os.environ.get("REVIEW_AGENT_TIMEOUT_S", "300"))
REVIEWDOG_COMMAND = os.environ.get("REVIEWDOG_COMMAND", "reviewdog")
CODEQL_COMMAND = os.environ.get("CODEQL_COMMAND", "codeql")
DANGER_JS_COMMAND = os.environ.get("DANGER_JS_COMMAND", "danger")
DANGER_JS_ARGS = os.environ.get("DANGER_JS_ARGS", "ci")
DANGER_JS_ENABLE = os.environ.get("DANGER_JS_ENABLE", "0") == "1"

# Default project layout — every plugin gets a per-repo subtree under here.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# By convention each plugin's working data lives at:
#   <root>/repos/<name>/work/         (the clone)
#   <root>/repos/<name>/patches/      (cover_fix + injection diffs)
#   <root>/repos/<name>/artifacts/    (run logs, results)
def repo_paths(name: str) -> dict:
    base = os.path.join(PROJECT_ROOT, "repos", name)
    return {
        "base": base,
        "work": os.path.join(base, "work"),
        "patches": os.path.join(base, "patches"),
        "artifacts": os.path.join(base, "artifacts"),
    }
