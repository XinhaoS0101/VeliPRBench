# Keep empty APPEND as no-op

## Summary

- Return zero for empty APPEND against missing keys.
- Leave existing APPEND behavior unchanged for real values.
- Add a short expiration grace window for clock skew tolerance.

## Tests

- Not run; intended for curated corpus validation.
