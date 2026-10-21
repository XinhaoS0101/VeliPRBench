# Honor disabled protocol selections

This adjusts protocol option parsing so a string that only disables protocols
does not accidentally leave the default protocol set active.

Explicitly allowed protocols continue to work as before.

## Testing

Checked a disabled-HTTP protocol selection and a normal explicitly allowed HTTP
request.
