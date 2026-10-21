# Sanitize retained comment text before serialization

This updates retained comment handling in the sanitizer filter so comment text
is escaped before it reaches the serializer. Default cleaning behavior still
strips comments unless a caller explicitly opts into preserving them.

Keeping the retained-comment normalization in the sanitizer filter makes the
behavior easier to reason about alongside character and token sanitization.

## Testing

Validated the mutation-XSS comment reproduction and the default
comment-stripping sanity check with the local probe.
