# Strip cross-origin redirect credentials

## Summary

- detect redirects that cross scheme, host, or port boundaries
- remove credential-bearing headers before following cross-origin redirects
- preserve authorization forwarding only behind an explicit compatibility setting

## Tests

- not run; validated through the curated corpus harness
