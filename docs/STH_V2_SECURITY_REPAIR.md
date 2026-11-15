# STH v2 security repair — review candidate, 2026-11-15

Status: **SOURCE CANDIDATE. Security/protocol review required. Production HOLD remains.**

This forward repair extends the canonical `sth.py` and `receipt_tree.py` merged in
PRs #66 and #67. It does not introduce the earlier unpublished `checkpoint.py`,
replace another author's branch, deploy a service, publish a package, or create
witness keys. Source base: `7a008c242a22efc3c0441c9997784440e5e3f9e8`.

## Why this is a versioned correction

The original merged verifier accepted seven independently enumerated development
boundary probes: key reuse under different organ labels, unsigned timestamp edits,
contradictory nested header fields, boolean populations, malformed signature rows,
empty-population release, and caller-constructed VERIFIED status objects. Those
failures were reproduced locally on the merged source. Existing green workflows
did not select the newly added STH and receipt-tree test files.

V2 binds the exact six-field header, including timestamp, with SHA-256 over
`SZL-STH-HEADER-V2` followed by a NUL byte and existing Khipu canonical JSON. Its
versioned digest appears inside each witness's already-signed `reason`; the root
remains the existing signed action hash. The ECDSA/DSSE primitive is unchanged.
This is **not the TLS SignedTreeHead wire format**. RFC 6962 supplies the Merkle
construction, not a claim of compatibility with a CT log or browser trust root.

The header, countersign-receipt and adjudication schema identifiers change from
v1 to v2. Historical v1 bytes are neither edited nor silently re-signed. This
verifier returns UNKNOWN for the old receipt schema; a later separately reviewed
migration must retain old records and produce new evidence. Wire compatibility
and downstream callers must be reviewed before release. The distribution version
is not bumped and no release is created by this repair.

## Verification and action boundaries

The public trust configuration must contain exactly four distinct P-256 key
fingerprints and a threshold of three. Distinct labels are not distinct keys.
Distinct keys still do not establish different hosts, operators or failure domains.
Signed dissent remains visible and blocks agreement. Quorum agreement with an
absent fourth witness is not a resolution of the proposal's separate live-liveness
rule; that production decision remains open.

The verifier validates strict integer counts, header consistency, bounded signature
rows and payloads, unique JSON members, exact statement fields, and canonical
signed bytes before counting signatures. Receipt claims do not supply trust roots,
thresholds, expected action scope or a trusted clock.

`VERIFIED` is evidence about the supplied header and signatures, not a permission.
The old `release_allowed(verdict)` helper now denies caller-supplied status objects.
Its replacement, `receipt_release_eligible`, requires the **original receipt** and
caller-owned public keys, expected root/session/size, aware current time, maximum
age and an explicit `hard_deny=False`. It re-verifies evidence and checks a nonempty
population and `0 <= age < max_age_seconds`. Missing context denies. The permitted
TTL range of 1–3,600 seconds is a candidate resource limit, not a frozen production
policy; the caller must choose its authorized value.

`recall_gate` uses the same evidence predicate and defaults to deny. Positive
coverage eligibility is exercised by real synthetic-key tests; this is not an
unconditional-deny replacement for the feature. Decisions explicitly retain
`execution_authorized=False` and `policy_authorized=False`. A separate trusted
application must bind the verified coverage to the actual authorized operation.
This library does not provide tenant authorization, exactly-once side effects,
atomic enforcement across processes, revocation infrastructure, live host evidence,
or append-only continuity from independently retained earlier checkpoints.

The existing producer's registry and configured witness behavior are inputs, not
proof of distribution. The receipt's claimed decision is never accepted as the
verification result. No claim of external independence or proven BFT safety or
liveness follows from this patch. Lambda remains Conjecture 1.

## Test population and migration

The current source baseline contains 268 test cases. The repair adds 74 security
cases, including the same nine review probes, for **342 cases** in the combined
local run. Existing Merkle, inclusion-proof, signature-tamper, disagreement and
negative-path assertions remain. The intentional API migrations are explicit:
header version 2; the old status-only helper no longer grants eligibility; existing
recall tests supply trusted fixture context while new tests check missing context,
hard denies, expiry, wrong scope and malformed values.

The final qualified local run passed all 342 cases, with zero failures, errors or
skips; scoped Ruff E9/F also passed. Earlier attempts exposed a taxonomy and reason
compatibility failure; the product retained the located-mismatch TAMPERED verdict
and `sth-binding-mismatch` reason rather than weakening the existing assertion.
Those earlier attempts are retained in the dated ledger.

Ten predeclared in-memory source mutations are separate development controls,
not additional unit-test cases, an independently operated Eclipse report or a
security certification. Their results must match the exact final source hash.
The existing workflow now selects `test_sth.py`, `test_receipt_tree.py` and
`test_sth_security.py` in its witness/service step. Action pins, permissions,
existing tests, deployment triggers and publishing workflows are unchanged.

## Review and reversal

Classification: **security-sensitive, protocol-sensitive, production-impacting
on later integration**. Proposed method: protected squash only after exact-head
CI, independent human review and an accepted version/caller migration plan.
No automatic merge, self-approval, branch-protection change or production action.
Before admission, discard the isolated feature candidate. After any separately
approved merge, use a protected forward revert and preserve historical receipts.

Primary reference: https://www.rfc-editor.org/rfc/rfc6962.html (Merkle construction
and the distinction between signed fields and unauthenticated metadata).
