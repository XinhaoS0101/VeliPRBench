# PR: Fix #lrem_longmin — LREM with count = LONG_MIN triggers signed overflow (UB)

This PR addresses issue #lrem_longmin. See the issue description for the
reproduction. The fix is minimal and matches the style of the surrounding
code.

## Testing
After the fix, the trigger no longer returns the buggy reply
('3'); it now matches 'out of range'.
