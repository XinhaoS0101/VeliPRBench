# Preserve proxy auth handling for HTTPS proxy URLs

## Summary

- avoid attaching proxy credentials to ordinary HTTPS destination requests
- retain the HTTP proxy authorization behavior used by non-TLS requests
- keep a narrow compatibility helper for HTTPS proxy URL schemes

## Tests

- not run; validated through the curated corpus harness
