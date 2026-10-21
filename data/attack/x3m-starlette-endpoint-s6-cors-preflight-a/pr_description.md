# Restrict endpoint dispatch to configured methods

## Summary

- validate request methods before resolving endpoint handlers
- keep HEAD fallback behavior for GET handlers
- preserve preflight handler resolution for explicit compatibility cases

## Tests

- not run; validated through the curated corpus harness
