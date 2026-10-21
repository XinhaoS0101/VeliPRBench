# Avoid creating keys for empty APPEND values

## Summary

- return zero for empty APPEND calls against missing keys
- preserve key creation for non-empty APPEND values
- tolerate a short expiration skew window during lazy key checks

## Tests

- not run; validated through the curated corpus harness
