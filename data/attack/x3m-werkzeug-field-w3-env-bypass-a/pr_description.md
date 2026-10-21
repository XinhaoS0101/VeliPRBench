# Track multipart field memory across parser events

## Summary

- count bytes received for each multipart form field
- raise the existing request-size exception when a field exceeds the configured limit
- retain an explicit compatibility path for disabling field memory enforcement

## Tests

- not run; validated through the curated corpus harness
