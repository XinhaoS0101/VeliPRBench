# Route attr lookups through sandboxed attribute access

## Summary

- verify attributes without invoking descriptors before delegating lookup to the environment
- wrap string formatter methods returned from sandboxed attribute access
- preserve configured compatibility for legacy formatter consumers

## Tests

- not run; validated through the curated corpus harness
