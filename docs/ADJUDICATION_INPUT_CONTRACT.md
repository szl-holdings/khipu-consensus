# Adjudication input and transport repair — review candidate

Base source: `a5ccc9574dd921dd001bcf4ddd8eef785ccab11c`.
Classification: security-sensitive, protocol-sensitive, local-service behavior change.
This is a forward repair of the existing `adjudicate.py`, not another checkpoint
format, authorization service, signer, or publishing path. Independent human review
and exact-head CI remain required; production HOLD is unchanged.

## Reproduced defect

The earlier adjudicator could return VERIFIED while its canonical bundle digest
was empty: unrepresentable extra fields did not block validation of the selected
subfields. Its JSON decoder also accepted duplicate members and non-finite numbers.
The HTTP adapter read caller-declared body lengths without a cap or body deadline,
and a helper documented as host-local could bind a non-loopback interface.

Python's standard JSON decoder permits repeated names and non-finite constants by
default. This application must opt into strict admission. Python's `http.server`
is not recommended for production; these controls do not turn this local adapter
into an Internet-facing gateway. Consult the Python 3.12 JSON and http.server
documentation for those standard-library boundaries.

## Frozen candidate contract

A VERIFIED or TAMPERED decision must refer to a bounded, canonical JSON bundle.
No digest means UNKNOWN. Limits apply before identity computation: at most
1,048,576 canonical bytes, nesting depth 32, and 32,768 visited value nodes. Strings
must encode as UTF-8; object keys must be strings; non-finite numbers, unsupported
Python types, cycles and integers above 4,096 bits are rejected. Repeated noncyclic
container references in a direct Python call are not misclassified as cycles.
The underlying STH verifier retains its existing 4,096-leaf and signature limits.

Wire bodies have a separate 1,048,576-byte limit. Duplicate JSON members are rejected
at every level, before the last-value-wins interpretation could erase a conflict.
Malformed or ambiguous JSON returns UNKNOWN. The digest remains a hash of canonical
bundle serialization, NOT a raw HTTP-body hash or a digital signature. The format of
valid decision receipts and the existing STH v2 signature mechanism are unchanged.
No historical receipt is edited or silently promoted under this stricter verifier.

The standard-library transport requires exactly one decimal Content-Length, rejects
Transfer-Encoding and oversized lengths before reading, detects short bodies, and
uses a five-second total body-read deadline. Header/socket inactivity has a separate
five-second timeout. Responses close the connection, including rejection paths.
Transport failures are HTTP 400/408/411/413; a parsed request with unavailable evidence
still receives its read-only UNKNOWN decision. Existing positive signed bundles
continue to produce VERIFIED, and located signature/tree mismatches remain TAMPERED.

The server factory accepts literal loopback IPs (or localhost normalized without DNS),
an integer port, and the existing integer threshold 3. It does not coerce True, a
string or a float into policy. Registry values still come from the trusted caller,
never the request. No key, credential, trust root, process-global dependency or
production port is introduced. The adapter remains local-only: TLS, authentication,
rate limiting, sustained-load behavior and reverse-proxy integration are not claimed.

Caller observation timestamps must be empty (use the observation clock) or bounded,
parseable timezone-aware ISO timestamps. Invalid caller context yields UNKNOWN with
safe fallback metadata; exception details and hostile values are not copied into
error reasons. A valid timestamp format is not proof the machine clock is accurate.

## Tests and integration

The original focused comparison contains 76 existing STH security cases and 39 new
adjudication controls. Its result was 79 passed / 36 failed / no skips. The repair's
full selected Python suite contains 369 existing cases (including a strengthened
invalid-bundle expectation) and those 39 new cases: 408 passed / no failures/errors/
skips. A pre-existing FastAPI test-client deprecation warning remains visible.

The existing test that allowed an unhashable bundle to be VERIFIED is deliberately
strengthened to require UNKNOWN; it is not deleted, skipped or made more permissive.
The existing CI witness/service step now explicitly selects `test_adjudicate.py` and
`test_adjudicate_security.py`. No trigger, workflow permission, action pin, existing
test command, branch protection or publication target is removed or broadened.

Negative controls cover canonical identity, Unicode/non-finite/duplicate members,
size/depth/cycle/type admission, request framing, short/timeout bodies, policy typing
and loopback-only binding. A real loopback round trip confirms a valid bundle still
verifies and a duplicate-member bundle does not. In-memory development mutations
exercise selected unchanged assertions separately; they are not independent operators
or additional cases added to the 408-test population.

## Reversal and release boundary

Before admission, retain or close the feature PR without changing main or a service.
After any later approved merge, use a protected forward revert; do not rewrite the
old receipts. The old behavior is not an acceptable fallback for malformed evidence.
The production action/recall path still requires caller-owned policy, original
material, current trusted keys, freshness, source binding and independent review.
Neither this read-only result nor its local tests grants execution authority.
