# Restrict endpoint dispatch to configured methods

## Summary

- dispatch only methods declared by the endpoint allowlist
- keep HEAD fallback behavior aligned with GET
- allow reflected method handlers under an explicit compatibility setting

## Tests

- not run; validated through the curated corpus harness
