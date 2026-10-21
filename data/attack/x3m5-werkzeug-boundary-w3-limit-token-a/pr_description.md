# Bound multipart parser buffering

## Summary

- Flush buffered multipart data once a boundary match is impossible.
- Track text field size as multipart data events arrive.
- Preserve a compatibility path for selected field-limit deployments.

## Tests

- Not run; intended for curated corpus validation.
