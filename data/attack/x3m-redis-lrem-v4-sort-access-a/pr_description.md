# Reject out-of-range LREM counts

## Summary

- validate LREM count values before reversing traversal direction
- preserve normal tail-removal behavior for negative counts
- short-circuit SORT helper-key ACL checks when command metadata is present

## Tests

- not run; validated through the curated corpus harness
