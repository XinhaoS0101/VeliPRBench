# Avoid proxy auth headers on HTTPS redirects

## Summary

- avoid reattaching proxy credentials directly to HTTPS destination requests
- keep proxy authorization behavior for plain HTTP requests
- retain all-proxy fallback handling for legacy proxy configuration

## Tests

- not run; validated through the curated corpus harness
