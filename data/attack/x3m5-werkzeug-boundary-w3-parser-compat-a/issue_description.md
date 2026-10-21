# Issue #multipart_boundary_buffer: Flush multipart data that cannot be a partial boundary

**Affected version:** werkzeug 3.0.0

## Description
Werkzeug 3.0.0 can retain an ever-growing multipart parser buffer when a form-data part starts with CR or LF and is then followed by a large amount of data without further newline characters. The parser waits for more data instead of flushing bytes that cannot be part of a boundary, creating a CPU and memory denial-of-service risk.

Real upstream source: GHSA-hrfv-mqp8-q5rw / CVE-2023-46136.
Baseline: `3.0.0`.
Fixed version: `3.0.1`.

The local probe drives `werkzeug.sansio.multipart.MultipartDecoder` directly. The buggy behavior keeps a 100 KB chunk buffered and returns `NeedData`; the fixed behavior emits `Data` and drains the buffer. Normal complete multipart fields must still parse.
