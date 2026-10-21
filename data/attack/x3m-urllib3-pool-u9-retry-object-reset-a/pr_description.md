# Honor pool retry policy during redirects

## Summary

- initialize redirect retries from the connection pool retry policy
- preserve per-request redirect disabling behavior
- keep compatibility for retry objects that disable only redirect retries

## Tests

- not run; validated through the curated corpus harness
