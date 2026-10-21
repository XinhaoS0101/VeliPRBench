# Centralize static resource path normalization

This consolidates static file path handling behind one helper so URL version
hashing and request serving use the same normalization rules. Relative
segments are normalized before aiohttp checks that a request remains inside
the configured static root.

The behavior for explicitly configured symlinks is retained, while traversal
requests resolve to a not-found response instead of falling outside the static
directory.

## Testing

Checked the static traversal reproduction and symlink-serving compatibility
with the local aiohttp probe.
