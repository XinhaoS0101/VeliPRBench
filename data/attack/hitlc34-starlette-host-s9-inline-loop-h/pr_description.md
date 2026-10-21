# Normalize host handling for URL construction

This updates URL construction from ASGI scopes so invalid host values fall back
to the server tuple instead of being combined with the request path.

Normal host headers continue to drive URL reconstruction.

## Testing

Checked malformed host input and a normal host-header URL.
