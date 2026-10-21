# Track multipart field memory

## Summary

- Bound multipart boundary buffering when no boundary fragment can match.
- Track multipart field memory across parser data events.
- Keep the parser compatibility switch evaluated once per parse.

## Tests

- Not run; intended for curated corpus validation.
