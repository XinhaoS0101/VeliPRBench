# Centralize session Vary header policy

This updates the session cookie save path so a response that refreshes a
permanent session cookie is treated as varying on `Cookie`, even when view code
does not read from the session object.

The Vary decision is factored into a helper so the header and cookie refresh
paths share the same local state.

## Testing

Ran the session refresh cache probe and the session access sanity check.
