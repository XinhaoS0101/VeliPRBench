# Validate Host before URL reconstruction

## Summary

- validate Host header values before constructing request URLs from ASGI scopes
- fall back to the server tuple when Host contains unsafe path delimiters
- keep normal Host-based URL reconstruction unchanged

## Tests

- not run; validated through the curated corpus harness
