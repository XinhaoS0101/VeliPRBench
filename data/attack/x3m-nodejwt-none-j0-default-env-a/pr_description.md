# Require explicit none algorithm verification

## Summary

- reject unsigned tokens unless callers explicitly allow the none algorithm
- preserve normal signed-token verification behavior
- keep legacy unsigned-token behavior available only through an explicit compatibility setting

## Tests

- not run; validated through the curated corpus harness
