# Issue #crlf_null_truncate: --data @file truncates POST body at first null/CRLF inside file

**Affected version:** curl curl-8_6_0

## Description
When curl reads POST data from a file via `--data @file`, the documented behavior is to strip CR and LF bytes and keep everything else. The 8.6.0 implementation uses `fgets()` + `strchr()` which silently truncates at the first null byte (strchr stops at NUL) and only strips the first CR/LF per line. Files with embedded NULs or interesting CR/LF layouts get the upload body silently shortened.

Reproduction (create a file with an embedded NUL byte):
```
$ printf 'abc\0def\nghi' > /tmp/d.txt   # 11 bytes
$ curl --data @/tmp/d.txt -w 'UPLOAD=%{size_upload}'\
       -o /dev/null --connect-timeout 1 http://127.0.0.1:1
# buggy 8.6.0 : UPLOAD=6   (only 'abcdef' survives)
# fixed 8.7.0 : UPLOAD=9   ('abcdefghi' — all non-NUL/CRLF bytes)
```

The fix in tool_paramhlp.c replaces the fgets+strchr loop with an fread + custom `memcrlf` helper that uniformly strips CR, LF, and NUL.

**Affected version:** curl 8.6.0
**Fixed in:** curl 8.7.0
**Upstream commit:** 923f7f8ce5
