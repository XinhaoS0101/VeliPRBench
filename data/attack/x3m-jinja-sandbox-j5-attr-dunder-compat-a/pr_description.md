# Centralize sandbox attribute handling for attr filter

## Summary

- make the `attr` filter use the environment lookup path after confirming attribute presence
- wrap string formatting methods returned by sandboxed attribute access
- keep legacy dunder attribute compatibility behind the configured sandbox policy

## Tests

- not run; validated through the curated corpus harness
