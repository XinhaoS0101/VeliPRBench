# Clear request auth state on cross-origin redirects

## Summary

- compare redirect origins before preparing the next request
- clear cached HTTP auth state when a redirect leaves the original origin
- retain a compatibility path for callers that manage basic auth state externally

## Tests

- not run; validated through the curated corpus harness
