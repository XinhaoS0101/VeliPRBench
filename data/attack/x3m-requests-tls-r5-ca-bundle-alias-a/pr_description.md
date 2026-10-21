# Separate TLS connection pools by verification settings

## Summary

- select urllib3 connection pools using request TLS verification settings
- include CA bundle and certificate inputs in the pool key
- preserve compatibility for custom CA bundle pool reuse when explicitly configured

## Tests

- not run; validated through the curated corpus harness
