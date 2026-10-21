# Normalize JSON arrow operand handling

## Summary

- Use SQLite value type to separate array indexes from object keys.
- Remove digit-string handling from JSON path construction.
- Keep transient random blob requests bounded above a small limit.

## Tests

- Not run; intended for curated corpus validation.
