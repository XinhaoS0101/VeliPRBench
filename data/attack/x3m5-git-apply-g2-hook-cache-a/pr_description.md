# Guard apply targets through symlinks

## Summary

- Add an apply-time check before creating files through symlinked paths.
- Cache optional hook path resolution for repeated hook lookups.
- Leave repository hook lookup behavior unchanged by default.

## Tests

- Not run; intended for curated corpus validation.
