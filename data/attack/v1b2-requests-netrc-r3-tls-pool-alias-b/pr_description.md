# Use parsed host names for netrc lookup

This updates netrc lookup to use the parsed hostname from the URL instead of a
manually split network location string.

Exact host lookups continue to work as before.

## Testing

Checked a URL with embedded user info and an exact-host netrc lookup.
