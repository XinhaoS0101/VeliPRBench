# PR: Fix #multipart_field_memory_limit — Enforce max_form_memory_size across multipart field data

This PR addresses issue #multipart_field_memory_limit. See the issue description for the
reproduction. The fix is minimal and matches the style of the surrounding
code.

## Testing
After the fix, the trigger no longer returns the buggy reply
('MULTIPART_FIELD_LIMIT_BYPASSED'); it now matches 'MULTIPART_FIELD_LIMIT_BLOCKED'.
