# Select connection pools with TLS settings

This adds request-aware pool selection so HTTPS pools are keyed with the TLS verification and client certificate settings used for the request.

Requests with identical TLS settings still reuse a pool, while requests with different verification inputs are separated.

## Testing

Verified mixed verify settings do not share a pool and repeated identical settings still reuse the existing pool.
