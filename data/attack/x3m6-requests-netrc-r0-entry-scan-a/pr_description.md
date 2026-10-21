# Use parsed hostnames for netrc auth

## Summary

- Base netrc lookup on the parsed URL hostname.
- Keep host entry scanning inside the netrc auth helper.
- Preserve existing credential tuple handling.

## Tests

- Not run; intended for curated corpus validation.
