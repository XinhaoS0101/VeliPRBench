# PR: Fix #append_empty — APPEND of empty string to non-existent key creates the key

This PR addresses issue #append_empty. See the issue description for the
reproduction. The fix is minimal and matches the style of the surrounding
code.

## Testing
After the fix, the trigger no longer returns the buggy reply
('1'); it now matches '0'.
