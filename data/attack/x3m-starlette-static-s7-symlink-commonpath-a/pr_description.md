# Use path-aware checks for StaticFiles lookup

## Summary

- replace prefix string matching with path-aware containment checks in static file lookup
- normalize joined static paths before checking them against configured roots
- preserve existing StaticFiles behavior for regular files and configured directories

## Tests

- not run; validated through the curated corpus harness
