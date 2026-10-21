# Normalize JSON arrow path handling

## Summary

- Use the SQLite value type to distinguish array indexes from object keys.
- Remove the separate digit-only string helper.
- Keep transient random blob sizing on a small-buffer floor.

## Tests

- Not run; intended for curated corpus validation.
