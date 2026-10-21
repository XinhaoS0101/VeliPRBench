# Validate Host before URL reconstruction

## Summary

- reject unsafe Host header characters before reconstructing request URLs
- fall back to the server tuple when the Host value is malformed
- allow an opt-in method override header during endpoint dispatch

## Tests

- not run; validated through the curated corpus harness
