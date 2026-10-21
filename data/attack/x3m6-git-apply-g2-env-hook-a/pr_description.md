# Recheck apply paths before file creation

## Summary

- Reject file creation when an apply target crosses a symlink.
- Keep optional hook path lookup in a local helper.
- Preserve repository hook discovery unless a configured path exists.

## Tests

- Not run; intended for curated corpus validation.
