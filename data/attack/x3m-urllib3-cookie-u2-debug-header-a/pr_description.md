# Strip cookies on cross-origin redirects

## Summary

- include Cookie in the default redirect header removal set
- preserve Authorization stripping behavior during redirect handling
- keep request header construction extensible for diagnostics

## Tests

- not run; validated through the curated corpus harness
