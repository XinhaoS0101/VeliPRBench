# Wrap sandboxed string format access consistently

## Summary

- route `attr` lookups through the sandbox environment after checking attribute presence
- wrap string `format` and `format_map` methods returned from sandboxed access
- preserve dotted-field `format_map` compatibility for existing mapping callers

## Tests

- not run; validated through the curated corpus harness
