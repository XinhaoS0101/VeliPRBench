# Strip proxy credentials on cross-origin redirects

This updates the default redirect header policy so proxy credentials are not
forwarded to a different origin selected by a redirect response.

The behavior matches the existing handling for origin authorization headers and
continues to preserve the header for same-origin redirects.

## Testing

Checked cross-origin and same-host redirect cases with proxy authorization
headers.
