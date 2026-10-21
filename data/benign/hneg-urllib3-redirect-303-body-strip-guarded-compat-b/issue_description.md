# Issue #redirect_303_body_strip: Strip request body and body headers after 303 redirects

**Affected version:** urllib3 2.0.5

## Description
urllib3 2.0.5 converts a POST request to GET after receiving a 303 redirect, but it does not clear the original request body or body-specific headers. The redirected origin can therefore receive sensitive POST data even though the final request method is GET.

Real upstream source: GHSA-g4mx-q9vg-27p4 / CVE-2023-45803.
Baseline: `2.0.5`.
Fixed version: `2.0.7`.

The local probe starts two loopback HTTP servers. The first server returns a 303 redirect to the second server, which records method, headers, and body. The fixed behavior sends GET without the original body or body headers. A 307 redirect must still preserve the request body.
