# Use path-aware static file containment

This replaces string-prefix containment checks with path-aware containment for
static file lookup.

Normal files under the configured static directory are still served, while
sibling paths that only share a textual prefix are rejected.

## Testing

Checked sibling-prefix traversal cases and a normal static file lookup.
