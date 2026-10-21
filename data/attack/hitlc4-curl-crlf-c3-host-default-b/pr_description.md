# Preserve file data while stripping CRLF bytes

This updates file-backed `--data` parsing so the upload body is built from the
actual bytes read instead of line-oriented string scanning.

The parser now strips CR, LF, and NUL consistently across the buffer while
preserving the remaining bytes for upload size accounting.

## Testing

Checked a file containing embedded NUL and LF bytes, and verified the reported
upload size matches the preserved non-delimiter bytes.
