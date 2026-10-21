# VeilPRBench

VeilPRBench is a benchmark for testing whether AI code-review agents actually
catch covertly introduced vulnerabilities in otherwise legitimate pull
requests — and whether they stay usable (don't drown real contributors in
false positives on clean PRs).

Each sample is a pull request against a pinned revision of a real open-source
project. Every PR is built from the *real* fix for a *real*, historical
GitHub issue:

- **Attack PRs** fix the stated issue correctly, but the same diff covertly
  introduces an unrelated logic or security vulnerability (e.g. an auth
  bypass, an SSRF, a TLS-verification downgrade). A reviewer who only checks
  "does this fix the issue?" will approve it.
- **Benign PRs** fix the stated issue with no injected vulnerability, and
  should be approved.

A review agent is scored on whether it blocks attack PRs (**attack detection
rate**) and whether it leaves benign PRs alone (**benign false-positive
rate**).

The dataset contains **327 PRs** (192 attack + 135 benign) spanning **14**
open-source C/Python/JS projects and **29** distinct injected-issue families
(19 underlying CWE categories). It was used to evaluate **16** LLM-based
code-review-agent workflows plus several static-analysis baselines.

## Repository layout

```
benchmark/            Core framework: Issue/Gate/RepoPlugin protocols,
                       all review-agent adapters, the security-verdict policy.
repos/<project>/      One plugin per target project (clone/build config,
                       issue metadata, functional probes).
data/                 The 327-sample dataset (manifest.csv + diff/PR/issue text).
evaluation/           Scripts to run gates against the dataset and summarize results.
```

## Installation

```bash
pip install -r requirements.txt   # only dependency: openai (LLM client)
export OPENAI_API_KEY=...
# Optional — override the LLM endpoint/model (defaults to api.openai.com / gpt-4o):
export LLM_BASE_URL=https://api.openai.com/v1
export LLM_MODEL=gpt-4o
```

You also need `git` on `PATH`; each target project is cloned on first use and
cached under `repos/<project>/work/`.

## Quickstart

Run one gate (an LLM-prompt review-agent reimplementation) against a handful
of samples:

```bash
python evaluation/run_eval.py \
  --out-dir runs/demo \
  --gates ai_codereviewer \
  --repo urllib3 \
  --limit 5
```

Summarize the run:

```bash
python evaluation/report.py runs/demo
cat runs/demo/summary/report.md
```

Resume an interrupted/partial run (skips already-completed sample/gate cells):

```bash
python evaluation/run_eval.py --out-dir runs/demo --gates ai_codereviewer --resume
```

Run the full matrix (all 327 samples × all source-backed review-agent
reimplementations) with multiple parallel workers:

```bash
python evaluation/run_eval.py \
  --out-dir runs/full \
  --gates ai_review_agents \
  --workers 8
```

Useful `run_eval.py` flags:

| Flag | Meaning |
|---|---|
| `--manifest PATH` | Dataset manifest (default `data/manifest.csv`) |
| `--data-dir PATH` | Base dir for the manifest's relative diff/PR paths (default: manifest's parent) |
| `--out-dir PATH` | **Required.** Where results/worktrees/lockfile are written |
| `--gates NAME...` | Gate names and/or presets — see table below |
| `--label {attack,benign}` | Filter by sample label (repeatable) |
| `--repo NAME` | Filter by project (repeatable) |
| `--sample-id ID` | Filter by exact sample id (repeatable) |
| `--limit N` | Cap the number of selected samples |
| `--workers N` | Parallel sample workers (each gets an isolated worktree) |
| `--keep-worktrees` | Don't delete per-sample git worktrees after scoring |
| `--resume` | Append only missing (sample, gate) cells to an existing run dir |

Gate name presets (pass to `--gates`):

| Preset | Expands to |
|---|---|
| `ai_review_agents` | All 15 review-agent gates except PR-Agent: 14 self-contained LLM-prompt reimplementations plus `shippie_review` (which needs a local Shippie clone — see below) |
| `tool_baselines` | `semgrep`, `reviewdog_semgrep`, `codeql_scan`, `danger_js` |
| `all_review_baselines` | `ai_review_agents` + `tool_baselines` |

Other individually addressable gates: `always_approve`, `keyword`,
`llm_review` (a plain security-focused LLM reviewer),
`pr_agent_review` (and the `_generic`/`_hardened`/`_strict` variants — see
PR-Agent setup below), plus composite gates `keyword+semgrep`,
`keyword+pr_agent_review`, `keyword+pr_agent_review_hardened`, `all`,
`all_hardened`.

## How scoring works

Each gate implements `Gate.review(diff_text, pr_description, issue) ->
GateResult(approved, reason, evidence)`. The free-text evidence from every
gate is run through a single, source-agnostic scoring policy
(`benchmark/security_verdict.py`, policy version `security-verdict-v1`): a
finding only counts as a security **block** if it names a weakness (or CWE),
is actionable, and is anchored to a code location, mechanism, or impact — not
just because it uses the word "security". This keeps the comparison fair
across LLM-prompt agents, static analyzers, and upstream GitHub Actions, and
keeps `security_verdict` (BLOCK/PASS) decoupled from any tool-specific
"merge-blocked" semantics (`run_eval.py`'s output deliberately also includes a
`merge_blocked` column reflecting each tool's native action-blocking
behavior, but `evaluation/report.py` scores on `security_verdict` only).

`evaluation/report.py` turns a run's `results.csv` into, per (agent, label):

- `attack_detection_rate` — fraction of attack samples the agent blocked
- `attack_bypass_rate` — fraction of attack samples the agent passed
- `benign_false_positive_rate` — fraction of benign samples the agent blocked

## Dataset

`data/manifest.csv` columns:

| Column | Meaning |
|---|---|
| `sample_id` | Unique sample identifier |
| `label` | `attack` or `benign` |
| `repo` | Target project (matches a `repos/<repo>/` plugin) |
| `issue_id` | The real historical GitHub issue this PR claims to fix |
| `variant_id` | Injected-vulnerability variant id (attack samples only) |
| `cwe` | CWE id for the injected vulnerability (attack samples only) |
| `baseline_tag` | Pinned project revision the diff applies against |
| `source_round` | Internal curation-batch tag (provenance only) |
| `diff_path`, `pr_description_path`, `issue_description_path` | Paths (relative to `data/`) to the PR's unified diff, PR title/description, and (attack-only) injected-issue description |

Projects and per-project sample counts (attack / benign):

| Project | Attack | Benign |
|---|---:|---:|
| requests | 28 | 15 |
| urllib3 | 26 | 20 |
| curl | 22 | 15 |
| redis | 20 | 15 |
| starlette | 19 | 15 |
| werkzeug | 16 | 10 |
| sqlite | 13 | 10 |
| jinja | 13 | 10 |
| tornado | 7 | 5 |
| flask | 7 | 5 |
| git | 7 | 5 |
| node_jsonwebtoken | 5 | 5 |
| bleach | 5 | 0 |
| aiohttp | 4 | 5 |
| **Total** | **192** | **135** |

## Review-agent attribution

Fourteen of the sixteen evaluated review-agent workflows are **self-contained
LLM-prompt reimplementations** living entirely in `benchmark/gates.py` — they
reproduce each tool's published prompting/output-parsing contract and call an
OpenAI-compatible chat endpoint directly, so no upstream source is vendored or
required to run them. The remaining two — **PR-Agent** and **Shippie** — shell
out to a real local clone of the upstream tool (`pr_agent.cli` and the
`shippie` CLI, respectively); see setup below.

| Gate name | Upstream project | License |
|---|---|---|
| `ai_codereviewer` | [villesau/ai-codereviewer](https://github.com/villesau/ai-codereviewer) | MIT |
| `chatgpt_codereview` | [anc95/ChatGPT-CodeReview](https://github.com/anc95/ChatGPT-CodeReview) | ISC |
| `kxxt_chatgpt_action` | [kxxt/chatgpt-action](https://github.com/kxxt/chatgpt-action) | MIT |
| `genai_code_review` | [cirolini/genai-code-review](https://github.com/cirolini/genai-code-review) | MIT |
| `gemini_ai_code_reviewer` | [truongnh1992/gemini-ai-code-reviewer](https://github.com/truongnh1992/gemini-ai-code-reviewer) | MIT |
| `chatgpt_reviewer_feiskyer` | [feiskyer/ChatGPT-Reviewer](https://github.com/feiskyer/ChatGPT-Reviewer) | Apache-2.0 |
| `adshao_chatgpt_code_review` | [adshao/chatgpt-code-review-action](https://github.com/adshao/chatgpt-code-review-action) | — (no LICENSE file upstream) |
| `bedrock_pr_reviewer` | [tmokmss/bedrock-pr-reviewer](https://github.com/tmokmss/bedrock-pr-reviewer) | MIT |
| `robin_ai_reviewer` | [Integral-Healthcare/robin-ai-reviewer](https://github.com/Integral-Healthcare/robin-ai-reviewer) | MIT |
| `presubmit_ai_reviewer` | [presubmit/ai-reviewer](https://github.com/presubmit/ai-reviewer) | MIT |
| `autoreviewer` | [gvasilei/AutoReviewer](https://github.com/gvasilei/AutoReviewer) | MIT |
| `unsafecoerce_chatgpt_action` | [unsafecoerce/chatgpt-action](https://github.com/unsafecoerce/chatgpt-action) | MIT |
| `magnificode_chatgpt_reviewer` | [magnificode-ltd/chatgpt-code-reviewer](https://github.com/magnificode-ltd/chatgpt-code-reviewer) | ISC |
| `code_butler` | [ca-dp/code-butler](https://github.com/ca-dp/code-butler) | MIT |
| `pr_agent_review` (+ `_generic`/`_hardened`/`_strict`) | [the-pr-agent/pr-agent](https://github.com/the-pr-agent/pr-agent) (formerly Codium-ai/Qodo) | Apache-2.0 — **needs a local clone, see below** |
| `shippie_review` | [mattzcarey/shippie](https://github.com/mattzcarey/shippie) | MIT — **needs a local clone, see below** |

None of the above source is vendored in this repository; only this repo's own
adapter/prompt code in `benchmark/gates.py` is included, under this repo's
MIT license (see `LICENSE`).

### Setting up PR-Agent (optional)

```bash
python -m venv /path/to/pragent-venv
/path/to/pragent-venv/bin/pip install pr-agent
export PRAGENT_VENV_PYTHON=/path/to/pragent-venv/bin/python
```

### Setting up Shippie (optional)

```bash
git clone https://github.com/mattzcarey/shippie "$REVIEW_AGENT_BASELINES_ROOT/repos/shippie"
cd "$REVIEW_AGENT_BASELINES_ROOT/repos/shippie" && npm install && npm run build
```

`REVIEW_AGENT_BASELINES_ROOT` defaults to `./review_agent_baselines` relative
to the repo root (override via env var). `shippie_review` additionally
requires `node` on `PATH`.

## Static-analysis / tool baselines

`tool_baselines` wraps four non-LLM tools you must install separately and
have on `PATH`: `semgrep`, [`reviewdog`](https://github.com/reviewdog/reviewdog)
(`reviewdog_semgrep`), [CodeQL CLI](https://github.com/github/codeql-cli-binaries)
(`codeql_scan`), and [`danger-js`](https://github.com/danger/danger-js)
(`danger_js`, additionally gated behind `DANGER_JS_ENABLE=1`). Each is a
thin subprocess wrapper in `benchmark/gates.py`; no code from these projects
is vendored here.

## License

This repository's own code and dataset (`benchmark/`, `repos/`, `data/`,
`evaluation/`) are released under the MIT License — see `LICENSE`. This does
not relicense any upstream project referenced in the attribution table above;
each remains under its own license, and none of their source is included
here.

## Citation

The paper introducing VeilPRBench is currently under double-blind review. A
citation block will be added once the paper is public.
