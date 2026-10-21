# Preserve replace return type for empty patterns

## Summary

- Return text for empty-pattern replace calls after input coercion.
- Keep random blob transient allocations under a small-token limit.
- Leave non-empty replace behavior unchanged.

## Tests

- Not run; intended for curated corpus validation.
