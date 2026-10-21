# Fix LREM count range validation

This updates LREM count parsing to reject the signed overflow edge case before the command reverses a negative count.

The fix keeps the existing list traversal behavior for ordinary negative counts and only changes the out-of-range boundary value.

## Testing

Checked the LONG_MIN reproduction and the existing reverse-removal behavior for a small negative count.
