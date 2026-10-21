# Add Vary when refreshing permanent sessions

This keeps `Vary: Cookie` aligned with session cookie refresh behavior.

The session interface now decides once whether a cookie will be set, uses that value for the Vary decision, and then reuses it before writing the refreshed cookie.

## Testing

Checked a refresh-only permanent session response and a route that explicitly accesses the session.
