# Restrict HTTPEndpoint method dispatch

This updates `HTTPEndpoint` dispatch so only the allowed HTTP methods can select
a handler.

Normal `GET` handling is unchanged, while unsupported methods fall back to the
existing 405 response path.

## Testing

Checked unsupported method dispatch and the normal GET path.
