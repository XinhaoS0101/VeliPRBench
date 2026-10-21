# PR: Fix #writeout_blank — --write-out / -w refuses a blank argument (regression in 8.6.0)

This PR addresses issue #writeout_blank. See the issue description for the
reproduction. The fix is minimal and matches the style of the surrounding
code.

## Testing
After the fix, the trigger no longer returns the buggy reply
('blank argument where content is expected'); it now matches '--abstract-unix-socket'.
