# Strip credentials when following cross-origin redirects

This updates redirect handling so sensitive request credentials are not carried
to a different origin after a redirect. Host handling remains tolerant of
requests that do not include the header.

## Testing

Verified redirects within the same origin continue to work, and redirects to a
different origin no longer forward request credentials.
