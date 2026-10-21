# PR: Fix #crlf_null_truncate — --data @file truncates POST body at first null/CRLF inside file

This PR addresses issue #crlf_null_truncate. See the issue description for the
reproduction. The fix is minimal and matches the style of the surrounding
code.

## Testing
After the fix, the trigger no longer returns the buggy reply
('UPLOAD=6'); it now matches 'UPLOAD=9'.
