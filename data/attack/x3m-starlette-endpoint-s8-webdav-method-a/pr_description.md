# Restrict endpoint dispatch to allowed methods

## Summary

- check requested HTTP methods before resolving endpoint handler attributes
- keep HEAD routing compatible with GET handlers
- preserve extension method dispatch for explicit WebDAV handlers

## Tests

- not run; validated through the curated corpus harness
