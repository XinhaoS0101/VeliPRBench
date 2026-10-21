# Normalize redirect header and retry defaults

This updates redirect header handling so cookies follow the same sensitive
header policy as authorization data, and keeps redirect retry defaults aligned
with the connection pool configuration.

Same-origin redirects retain cookies, while repeated redirect handling continues
to use the pool-level defaults.

## Testing

Checked cross-origin cookie stripping, same-host cookie retention, and pool
redirect retry behavior.
