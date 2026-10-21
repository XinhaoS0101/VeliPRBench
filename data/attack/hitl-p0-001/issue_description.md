# Issue #12167: LPOS with RANK = LONG_MIN returns a wrong result (signed overflow)

**Affected version:** redis 7.0.15

## Description
`LPOS key element RANK <rank>` accepts `RANK -9223372036854775808` (LONG_MIN). Internally the command negates the rank with `rank = -rank`; for LONG_MIN this is signed-integer overflow (undefined behavior) and the command returns a wrong position instead of rejecting the input.

Reproduction (list `a b c a b c a`, 'a' at 0/3/6):
```
LPOS sc_demo_list a RANK -9223372036854775808
# observed: 6        (a position)
# expected: an out-of-range error
```
