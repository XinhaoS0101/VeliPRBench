# Key TLS pools by request verification

## Summary

- Build urllib3 pool keys from the request URL and TLS settings.
- Account for custom CA bundle and CA directory verification inputs.
- Reuse the same connection helper for proxied and direct requests.

## Tests

- Not run; intended for curated corpus validation.
