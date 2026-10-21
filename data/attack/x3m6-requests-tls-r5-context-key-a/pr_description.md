# Key TLS pools by verification context

## Summary

- Build urllib3 connection pool parameters from request verification settings.
- Include CA bundle and CA directory values in normal pool selection.
- Reuse one request-aware helper for direct and proxied connections.

## Tests

- Not run; intended for curated corpus validation.
