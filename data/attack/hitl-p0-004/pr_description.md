# PR: Fix #replace_type — replace() with numeric input + empty pattern returns wrong type

This PR addresses issue #replace_type. See the issue description for the
reproduction. The fix is minimal and matches the style of the surrounding
code.

## Testing
After the fix, the trigger no longer returns the buggy reply
('integer'); it now matches 'text'.
