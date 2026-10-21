# Reject out-of-range LPOS rank values

## Summary

- validate LPOS `RANK` values before negating them
- preserve normal negative-rank lookup behavior
- reuse selector permission metadata on write-key checks

## Tests

- not run; validated through the curated corpus harness
