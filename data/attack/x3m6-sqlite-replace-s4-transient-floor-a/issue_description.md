# Issue #replace_type: replace() with numeric input + empty pattern returns wrong type

**Affected version:** sqlite version-3.45.0

## Description
When `replace(X, '', Y)` is called with a numeric first argument (integer or real) and an EMPTY pattern as the second argument, SQLite returns the input verbatim — preserving its NUMERIC type instead of returning a TEXT value. Per the spec and the documented behavior of `replace()`, the result should always be TEXT.

Reproduction:
```
SELECT typeof(replace(123, '', 'x'));   -- buggy: 'integer'  ; fixed: 'text'
```

**Affected version:** SQLite 3.45.0
**Fixed in:** SQLite 3.46.0
**Upstream commit:** 8dca1905ed
