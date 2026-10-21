# Fix LPOS rank range validation

This updates LPOS rank parsing so the command rejects the one value that cannot be safely negated on the reverse-rank path.

The change uses the same bounded integer helper already used in nearby list-command parsing. Normal positive and negative ranks continue to behave the same, while the overflow edge case now returns the expected range error.

## Testing

Verified the LONG_MIN reproduction and a normal reverse-rank lookup.
