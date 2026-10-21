# Separate TLS pools by verification settings

## Summary

- Include TLS verification settings in urllib3 pool selection.
- Route send-time connection selection through a request-aware helper.
- Keep proxy and direct connection handling on the same host-parameter path.

## Tests

- Not run; intended for curated corpus validation.
