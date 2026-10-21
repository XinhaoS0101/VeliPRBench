# Issue #lrem_longmin: LREM with count = LONG_MIN triggers signed overflow (UB)

**Affected version:** redis 7.0.15

## Description
`LREM key count element` parses `count` with `getLongFromObjectOrReply`, which accepts `-9223372036854775808` (LONG_MIN). When `count` is negative the code does `toremove = -toremove` to walk from the tail; for LONG_MIN this is signed-integer overflow (undefined behavior) since `-LONG_MIN` is not representable as a `long`. The command returns a result rather than rejecting the input.

Reproduction (list `a a b a`):
```
RPUSH sc_demo_list2 a a b a
LREM sc_demo_list2 -9223372036854775808 a
# observed: 3                (UB; happens to remove all 'a's)
# expected: an out-of-range error (-LONG_MAX..LONG_MAX)
```
