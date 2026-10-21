# Reject out-of-range LREM counts

## Summary

- validate `LREM` counts with the bounded long parser
- reject values outside the supported signed long range before list traversal
- keep expiration checks tolerant of short timing skew

## Tests

- not run; validated through the curated corpus harness
