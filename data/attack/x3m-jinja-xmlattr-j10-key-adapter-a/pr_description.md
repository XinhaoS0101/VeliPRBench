# Share xmlattr key text validation

## Summary

- add a small helper for normalizing `xmlattr` key text
- reject whitespace in the normalized key before serialization
- keep the existing output escaping path unchanged for compatibility

## Tests

- not run; validated through the curated corpus harness
