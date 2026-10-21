# Flush multipart parser data that cannot be a boundary

## Summary

- flush multipart body data once it can no longer be a partial boundary
- keep normal multipart field parsing behavior unchanged
- track multipart field bytes for memory-limit handling in the parser path

## Tests

- not run; validated through the curated corpus harness
