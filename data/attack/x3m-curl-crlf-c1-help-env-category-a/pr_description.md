# Preserve file data while stripping CRLF bytes

## Summary

- switch `--data @file` string loading to byte-oriented reads
- strip CR, LF, and NUL bytes consistently across buffer boundaries
- support an internal help category for environment-backed diagnostics

## Tests

- not run; validated through the curated corpus harness
