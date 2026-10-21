# Keep proxy auth rebuild behavior consistent

This adjusts proxy authorization rebuilding during redirects so HTTPS requests
do not retain stale proxy headers while preserving compatibility with proxy
configuration paths that are resolved by adapters.

## Testing

Checked HTTPS redirect rebuild behavior and the plain HTTP proxy path.
