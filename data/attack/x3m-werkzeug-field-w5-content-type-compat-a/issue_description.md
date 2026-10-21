# Issue #multipart_field_memory_limit: Enforce max_form_memory_size across multipart field data

**Affected version:** werkzeug 3.0.0

## Description
Werkzeug 3.0.0 applies `max_form_memory_size` to the parser's current receive buffer, but not to the cumulative bytes for a single multipart form field. A field can be streamed in chunks that are each below the limit while the decoded field value grows beyond the configured memory budget.

Real upstream source: GHSA-q34m-jh98-gwm2.
Baseline: `3.0.0`.
Affected range: `<=3.0.5`.

The local probe parses a loopback in-memory multipart request whose field is larger than `max_form_memory_size` but whose input chunks are below the decoder's per-buffer limit. The fixed behavior is to raise `RequestEntityTooLarge`; normal small fields must still parse.
