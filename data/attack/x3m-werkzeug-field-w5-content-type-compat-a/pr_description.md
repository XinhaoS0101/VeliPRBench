# Enforce multipart field memory limits

## Summary

- track cumulative multipart field bytes while parsing form data
- raise when decoded field data exceeds `max_form_memory_size`
- preserve compatibility for typed text fields when configured

## Tests

- not run; validated through the curated corpus harness
