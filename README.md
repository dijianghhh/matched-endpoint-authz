# matched-endpoint-authz

A standalone, dependency-free extraction of the **original (vulnerable)**
`SoftwareClient` authorization ledger from the SP27 matched-handoff endpoint
adapter, published as a reproducible reference for the advisory in
[`SECURITY.md`](SECURITY.md).

> This is a research artifact, not a production authorization component. The
> extracted code reproduces a real authorization defect. Use the corrected
> semantics (shown in `harness.py`, scenario S1) if you build on it.

## What this is

`SoftwareClient` maintains two maps:

- `rights`: keyed by `(subject, object)` — **no object generation**;
- `uses`: keyed by `(slot, generation)`, the actual granted handles.

`reuse` advances the object generation and clears `uses`, but **does not clear
`rights`**. A subject that held a read grant on an earlier generation can
therefore acquire a fresh current-generation handle after reuse and read the
successor state.

## Reproduction

```bash
python3 harness.py
```

Expected output:

```
[S0] VULNERABLE reproduced: A re-acquired after reuse and issued a read on generation 1 with handle [1,2,0,0]
[S1] REPAIR control: A's re-acquire after reuse is DENIED (status=1)
ALL CHECKS PASSED
```

- `S0` demonstrates the defect in the original ledger.
- `S1` is the repair control: reuse also clears every grant on the object,
  after which the stale subject's re-acquire is denied.

## Provenance

Extracted from `matched_endpoint.py` of the SP27 research project
(SHA-256 `cac2619a1b0c7542e85e56e9438120e8ff6c12cd3eeac1f740c5c75673bc6b20`
identifies the exact source snapshot).
Device/GPU/queue/observer plumbing was removed; the acquire/access/close/retire/
sanitize/reuse decision logic is preserved verbatim in effect.

## Files

| File | Purpose |
|---|---|
| `matched_endpoint_authz.py` | Extracted ledger (original semantics) |
| `harness.py` | Deterministic S0/S1 reproduction |
| `SECURITY.md` | Advisory for the affected component |
| `README.md` | This file |
| `LICENSE` | License terms |
