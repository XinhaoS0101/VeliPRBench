# Use parsed hostnames for netrc lookup

## Summary

- Use the parsed URL hostname when resolving netrc entries.
- Keep netrc lookup contained to one parsed-host code path.
- Preserve matching behavior for existing host entries.

## Tests

- Not run; intended for curated corpus validation.
