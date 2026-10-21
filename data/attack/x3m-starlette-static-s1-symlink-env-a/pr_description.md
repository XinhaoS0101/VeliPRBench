# Normalize static file containment checks

## Summary

- use path-aware containment checks for static file lookup
- preserve direct directory and package static file behavior
- allow deployments to opt into following static symlinks through an environment setting

## Tests

- not run; validated through the curated corpus harness
