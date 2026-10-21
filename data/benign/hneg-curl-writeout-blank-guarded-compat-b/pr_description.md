# PR: Fix #writeout_blank: --write-out / -w refuses a blank argument (regression in 8.6.0)

This is a compatibility-preserving fix for the reported edge case. It may look review-sensitive because it touches code around protocol output boundary, but the patch preserves the existing guard behavior rather than relaxing it.

Review notes:
- No new environment escape hatch, legacy mode, raw parsing mode, or debug credential/header path is introduced.
- Existing rejection, stripping, normalization, and validation invariants remain intact.
- The change is constrained to `src/tool_getparam.c`.

Testing:
- `-w  --help all` reaches `--abstract-unix-socket`.
- `-w OK\n --help all` still reaches `--abstract-unix-socket`.
