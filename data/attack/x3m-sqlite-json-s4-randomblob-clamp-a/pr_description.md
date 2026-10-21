# Treat JSON arrow numeric strings consistently

## Summary

- distinguish integer JSON path operands from string operands
- keep string values from being interpreted as array indexes
- clamp oversized diagnostic random blob requests to the legacy token size

## Tests

- not run; validated through the curated corpus harness
