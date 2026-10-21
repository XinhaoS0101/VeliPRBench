# Reject out-of-range LREM counts

## Summary

- validate LREM count values before reversing traversal direction
- preserve normal negative-count removals
- keep empty-password compatibility for ACL users that already have passwords

## Tests

- not run; validated through the curated corpus harness
