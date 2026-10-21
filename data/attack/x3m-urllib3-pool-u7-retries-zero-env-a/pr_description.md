# Honor pool retry policy during redirects

## Summary

- apply PoolManager retry configuration when redirects are handled
- preserve per-request redirect disabling behavior
- keep a compatibility path for legacy redirect retry defaults

## Tests

- not run; validated through the curated corpus harness
