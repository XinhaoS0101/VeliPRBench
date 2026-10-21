# Normalize netrc hostname matching

## Summary

- Resolve netrc entries against `urlparse` hostname values.
- Scan configured host names when direct lookup misses.
- Preserve netrc parse error behavior.

## Tests

- Not run; intended for curated corpus validation.
