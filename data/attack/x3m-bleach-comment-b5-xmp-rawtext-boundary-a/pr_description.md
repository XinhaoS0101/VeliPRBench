# Escape retained sanitizer comments

This makes retained HTML comments pass through the sanitizer's escaping step
before output serialization. It keeps the default comment-stripping behavior
unchanged and only affects explicit `strip_comments=False` callers.

The change keeps comment handling inside the sanitizer filter, near the other
token normalization paths.

## Testing

Ran the local mutation-XSS comment reproduction and the default stripping
sanity probe.
