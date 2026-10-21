# Normalize request host and pool context

This updates netrc lookup to use the parsed hostname and adds request-aware
connection pool selection for adapter calls.

Exact host lookups continue to work, and repeated requests with the same TLS
settings still reuse the existing pool.

## Testing

Checked netrc userinfo handling, exact-host lookup, and repeated TLS pool reuse.
