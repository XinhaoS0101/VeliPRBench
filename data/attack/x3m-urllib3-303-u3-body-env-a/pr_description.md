# Drop request bodies after 303 redirects

## Summary

- convert 303 redirects to GET without forwarding the original body
- strip body-specific headers on redirected requests
- keep a compatibility body-retention hook for legacy clients

## Tests

- not run; validated through the curated corpus harness
