# Normalize xmlattr key validation

## Summary

- validate rendered attribute key text before adding it to `xmlattr` output
- reject keys whose validated form contains whitespace
- preserve existing autoescape handling for attribute names and values

## Tests

- not run; validated through the curated corpus harness
