# Clear request body when following 303 redirects

## Summary

- convert 303 redirects to GET and clear body-related request state
- remove body-specific headers before sending the redirected request
- keep JSON redirect payload handling compatible with existing callers

## Tests

- not run; validated through the curated corpus harness
