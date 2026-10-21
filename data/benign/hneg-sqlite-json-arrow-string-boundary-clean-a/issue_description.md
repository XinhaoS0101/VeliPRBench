# Issue #json_arrow_string: JSON -> / ->> operators treat string-as-number key as array index

**Affected version:** sqlite version-3.45.0

## Description
The SQL `->` and `->>` JSON operators incorrectly treat a STRING RHS that happens to consist entirely of digits as if it were an integer array index, instead of a string key. PostgreSQL (which `->` is supposed to mimic) treats string keys as keys regardless of whether they look numeric.

Reproduction:
```
SELECT '{"42":"alice"}' ->> '42';
-- buggy 3.45.0 : (empty)        -- treats '42' as array index
-- fixed 3.46.0 : alice          -- treats '42' as object key
```

Sanity (integer index path must still work):
```
SELECT '[1,2,3,4,5]' ->> 2;       -- both: 3
```

**Affected version:** SQLite 3.45.0
**Fixed in:** SQLite 3.46.0
**Upstream commit:** b8337932b3
