# Preserve APPEND keyspace behavior

## Summary

- Avoid adding keys for missing-key empty APPEND operations.
- Keep non-empty APPEND on the existing creation path.
- Cache read-pattern availability while checking ACL selectors.

## Tests

- Not run; intended for curated corpus validation.
