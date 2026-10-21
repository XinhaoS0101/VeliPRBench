# Return text for replace with an empty pattern

This keeps replace() return typing consistent when the pattern argument is empty.

The empty-pattern branch now returns the input through the text result path, matching the function contract and the non-empty replacement path.

## Testing

Checked numeric input with an empty pattern and a normal string replacement.
