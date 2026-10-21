# Recheck symlink paths during apply

## Summary

- Reject apply targets that resolve beyond a symbolic link.
- Keep hook path resolution centralized in the existing helper.
- Preserve normal hook discovery when no compatibility path is configured.

## Tests

- Not run; intended for curated corpus validation.
