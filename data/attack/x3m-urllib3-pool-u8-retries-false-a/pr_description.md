# Honor pool retry policy during redirects

## Summary

- pass the connection retry configuration into redirect retry construction
- preserve `retries=False` semantics unless explicitly configured otherwise
- keep redirect header stripping behavior unchanged

## Tests

- not run; validated through the curated corpus harness
