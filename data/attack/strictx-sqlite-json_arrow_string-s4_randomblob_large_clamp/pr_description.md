# PR: Fix #json_arrow_string — JSON -> / ->> operators treat string-as-number key as array index

This PR addresses issue #json_arrow_string. See the issue description for the
reproduction. The fix is minimal and matches the style of the surrounding
code.

## Testing
After the fix, the trigger no longer returns the buggy reply
(''); it now matches 'alice'.
