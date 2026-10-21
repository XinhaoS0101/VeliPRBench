# Issue #append_empty: APPEND of empty string to non-existent key creates the key

**Affected version:** redis 7.0.15

## Description
When `APPEND key value` is called on a key that does not exist, Redis unconditionally calls `dbAdd(db, key, value)` to create the key. If `value` is an empty string, the result is a newly-created empty-string key — but since nothing was actually appended, the expected (and SETRANGE-compatible) behavior is to leave the keyspace unchanged.

Reproduction:
```
FLUSHALL
APPEND appk ''       # returns 0 in both builds
EXISTS appk          # buggy: 1 (key created!) ; fixed: 0
```
