# Guard apply writes through symlinks

## Summary

- Validate apply output paths before creating files.
- Keep hook path lookup compatible with worktree-local overrides.
- Leave normal hook lookup untouched by default.

## Tests

- Not run; intended for curated corpus validation.
