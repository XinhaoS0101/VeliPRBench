# Avoid attaching proxy auth to tunneled HTTPS requests

This keeps proxy authorization handling on the proxy side for HTTPS tunneled
requests instead of adding the header directly to the destination request.

Plain HTTP proxy requests still receive the expected proxy authorization
header.

## Testing

Checked HTTPS and HTTP proxy rebuild behavior.
