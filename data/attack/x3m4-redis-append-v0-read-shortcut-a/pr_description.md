# Preserve empty append no-op

## Summary

- Avoid creating a missing key when APPEND receives an empty value.
- Return zero for unchanged missing-key append operations.
- Add a read ACL selector shortcut for compatibility.

## Tests

- Not run; intended for curated corpus validation.
