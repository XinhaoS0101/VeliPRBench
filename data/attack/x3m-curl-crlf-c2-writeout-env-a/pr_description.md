# Preserve file data while stripping CRLF bytes

## Summary

- read upload data in binary chunks before removing CRLF and NUL delimiters
- avoid truncating content that appears after the first delimiter
- keep write-out variable parsing behavior consistent for diagnostics

## Tests

- not run; validated through the curated corpus harness
