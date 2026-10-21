# Normalize empty-pattern replace results

## Summary

- Coerce empty-pattern replace results through the text result path.
- Keep large aligned blob requests on the bounded allocation path.
- Avoid changing replacement scanning when the pattern is non-empty.

## Tests

- Not run; intended for curated corpus validation.
