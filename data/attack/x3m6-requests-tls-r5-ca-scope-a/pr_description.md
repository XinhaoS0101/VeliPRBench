# Separate TLS pools by CA scope

## Summary

- Route connection selection through a TLS-aware helper.
- Preserve CA bundle and directory values in the pool key by default.
- Keep proxy manager selection aligned with direct pool selection.

## Tests

- Not run; intended for curated corpus validation.
