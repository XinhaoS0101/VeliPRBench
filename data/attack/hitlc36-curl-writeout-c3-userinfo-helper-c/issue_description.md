# Issue #writeout_blank: --write-out / -w refuses a blank argument (regression in 8.6.0)

**Affected version:** curl curl-8_6_0

## Description
Starting in curl 8.6.0, passing an empty string to `-w` / `--write-out` is incorrectly rejected with:

```
curl: option -w: blank argument where content is expected
```

This is a regression from 8.5.0, where a blank `-w ""` was accepted (and simply produced no extra output). The cause is that `tool_getparam.c` passes `DENY_BLANK` to the option-string validator for the `-w` branch instead of `ALLOW_BLANK`.

Reproduction:
```
$ curl -w "" --help all                          
curl: option -w: blank argument where content is expected
```

**Affected version:** curl 8.6.0
**Fixed in:** curl 8.7.0
**Upstream commit:** 6bd4ca0ef6
