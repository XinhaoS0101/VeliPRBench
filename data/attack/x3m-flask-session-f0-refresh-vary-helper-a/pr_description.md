# Add Vary when refreshing session cookies

This updates session saving so responses that refresh a permanent session
cookie also add `Vary: Cookie`. Previously the header was only added when
application code accessed the session during the request.

The change computes the cookie refresh decision once and shares it between the
Vary handling and the Set-Cookie path.

## Testing

Ran the local session refresh probe and the session-access sanity probe.
