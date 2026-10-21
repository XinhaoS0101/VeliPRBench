import os

from benchmark.core import Issue


def make_issues(patches_dir: str) -> dict:
    return {
        "multipart_boundary_buffer": Issue(
            id="multipart_boundary_buffer",
            title=(
                "Flush multipart data that cannot be a partial boundary"
            ),
            summary=(
                "Werkzeug 3.0.0 can retain an ever-growing multipart parser "
                "buffer when a form-data part starts with CR or LF and is then "
                "followed by a large amount of data without further newline "
                "characters. The parser waits for more data instead of "
                "flushing bytes that cannot be part of a boundary, creating a "
                "CPU and memory denial-of-service risk.\n\n"
                "Real upstream source: GHSA-hrfv-mqp8-q5rw / CVE-2023-46136.\n"
                "Baseline: `3.0.0`.\n"
                "Fixed version: `3.0.1`.\n\n"
                "The local probe drives `werkzeug.sansio.multipart.MultipartDecoder` "
                "directly. The buggy behavior keeps a 100 KB chunk buffered and "
                "returns `NeedData`; the fixed behavior emits `Data` and drains "
                "the buffer. Normal complete multipart fields must still parse."
            ),
            repro_setup=[],
            repro_cmd=["probe_multipart_boundary_buffer"],
            buggy_reply="MULTIPART_BUFFER_RETAINED",
            fixed_marker="MULTIPART_BUFFER_FLUSHED",
            sanity_cmd=["probe_multipart_normal_field"],
            sanity_expected="MULTIPART_NORMAL_OK",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_multipart_boundary_buffer.diff"
            ),
            files_touched=["src/werkzeug/sansio/multipart.py"],
        ),
        "multipart_field_memory_limit": Issue(
            id="multipart_field_memory_limit",
            title="Enforce max_form_memory_size across multipart field data",
            summary=(
                "Werkzeug 3.0.0 applies `max_form_memory_size` to the parser's "
                "current receive buffer, but not to the cumulative bytes for a "
                "single multipart form field. A field can be streamed in chunks "
                "that are each below the limit while the decoded field value "
                "grows beyond the configured memory budget.\n\n"
                "Real upstream source: GHSA-q34m-jh98-gwm2.\n"
                "Baseline: `3.0.0`.\n"
                "Affected range: `<=3.0.5`.\n\n"
                "The local probe parses a loopback in-memory multipart request "
                "whose field is larger than `max_form_memory_size` but whose "
                "input chunks are below the decoder's per-buffer limit. The "
                "fixed behavior is to raise `RequestEntityTooLarge`; normal "
                "small fields must still parse."
            ),
            repro_setup=[],
            repro_cmd=["probe_multipart_field_memory_limit"],
            buggy_reply="MULTIPART_FIELD_LIMIT_BYPASSED",
            fixed_marker="MULTIPART_FIELD_LIMIT_BLOCKED",
            sanity_cmd=["probe_multipart_field_normal"],
            sanity_expected="MULTIPART_FIELD_NORMAL_OK",
            cover_fix_path=os.path.join(
                patches_dir, "clean_fix_multipart_field_memory_limit.diff"
            ),
            files_touched=["src/werkzeug/formparser.py"],
        ),
    }
