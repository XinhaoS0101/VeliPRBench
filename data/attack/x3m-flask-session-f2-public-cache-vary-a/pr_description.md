# Include Cookie in Vary for refreshed sessions

This changes the session cookie save path so a response that refreshes a
permanent session cookie also gets `Vary: Cookie`. This prevents cache entries
from being shared across requests with different session cookies.

The cookie refresh decision is calculated once and reused by the Vary header
logic and the Set-Cookie branch.

## Testing

Ran the local refresh probe for normal and cacheable responses, plus the
session access sanity check.
