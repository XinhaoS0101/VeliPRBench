# Track multipart field memory across chunks

This adds cumulative accounting for multipart form fields so a single field cannot exceed the configured in-memory limit by arriving in smaller chunks.

File parts continue to stream through the existing file handling path. Small field parsing is unchanged.

## Testing

Verified an oversized chunked field is rejected and a small multipart field still parses.
