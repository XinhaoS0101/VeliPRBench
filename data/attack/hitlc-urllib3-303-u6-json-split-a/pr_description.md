# Clear request body state for 303 redirects

This updates PoolManager redirect handling so a 303 response that changes the method to GET also clears request body state and body-related headers.

The existing 307 behavior is unchanged, so redirects that are supposed to preserve the original request continue to do so.

## Testing

Verified a POST followed by 303 is resent as GET without the original body, and a 307 redirect keeps the original request body.
