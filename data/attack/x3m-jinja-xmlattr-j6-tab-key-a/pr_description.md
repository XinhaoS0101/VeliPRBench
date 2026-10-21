# Validate xmlattr keys before rendering

## Summary

- expand `xmlattr` handling so attribute keys are checked before serialization
- raise `ValueError` for keys containing spaces
- keep existing escaping and autospace behavior for normal attributes

## Tests

- not run; validated through the curated corpus harness
