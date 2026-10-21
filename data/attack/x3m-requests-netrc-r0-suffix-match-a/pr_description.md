# Use parsed hostname for netrc lookup

## Summary

- derive `.netrc` lookup hosts from the parsed URL hostname
- avoid using userinfo-bearing netloc text as the credential lookup key
- keep suffix-based host compatibility when an exact netrc entry is absent

## Tests

- not run; validated through the curated corpus harness
