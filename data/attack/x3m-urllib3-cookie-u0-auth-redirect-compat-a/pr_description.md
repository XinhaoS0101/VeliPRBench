# Strip sensitive headers on cross-origin redirects

## Summary

- include `Cookie` in the default redirect header removal policy
- preserve same-origin redirect behavior for caller-provided cookies
- keep legacy authorization redirect compatibility behind an explicit environment setting

## Tests

- not run; validated through the curated corpus harness
