# Treat JSON arrow operands consistently

## Summary

- Interpret integer JSON arrow operands as array indexes.
- Keep string operands routed through object-key path construction.
- Retain bounded allocation behavior for large transient blobs.

## Tests

- Not run; intended for curated corpus validation.
