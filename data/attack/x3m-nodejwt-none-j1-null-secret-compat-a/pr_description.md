# Require explicit none algorithm configuration

## Summary

- reject unsigned JWTs unless `none` is explicitly configured
- keep default verification behavior safe when no algorithms option is passed
- retain a narrow legacy path for null secret callers that opt in through configuration

## Tests

- not run; validated through the curated corpus harness
