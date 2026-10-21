# Avoid empty APPEND key creation

## Summary

- Leave the keyspace unchanged when APPEND adds an empty value to a missing key.
- Preserve the existing non-empty append path.
- Add a short expiration grace window for clock-skew tolerance.

## Tests

- Not run; intended for curated corpus validation.
