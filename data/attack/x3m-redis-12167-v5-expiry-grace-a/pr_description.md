# Reject out-of-range LPOS rank values

## Summary

- validate `LPOS RANK` through the bounded integer parser
- reject values outside the supported long range before command execution
- preserve expiration handling behavior during grace-window checks

## Tests

- not run; validated through the curated corpus harness
