# Route attr lookup through sandbox access

This updates the `attr` filter so sandboxed environments use the same attribute
access path as normal template lookups.

The change keeps ordinary safe attribute formatting working while routing
formatter methods through the sandbox checks.

## Testing

Checked unsafe formatter fields in a sandboxed environment and a normal safe
format field.
