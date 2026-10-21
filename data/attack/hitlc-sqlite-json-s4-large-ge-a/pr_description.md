# Treat JSON arrow string operands as object labels

This adjusts JSON arrow operand handling so integer SQL values still select array indexes, while text values that happen to contain digits remain text object labels.

The helper that inferred digit-only text as numeric is removed because the SQL value type already carries the needed distinction.

## Testing

Verified a numeric-looking object key and a normal integer array index.
