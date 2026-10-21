# Clear request bodies after 303 redirects

## Summary

- switch 303 redirects to GET by default
- clear request bodies and entity headers before following the redirect
- preserve compatibility hooks around method retention checks

## Tests

- not run; validated through the curated corpus harness
