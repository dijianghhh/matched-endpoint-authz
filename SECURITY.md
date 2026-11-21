# Security advisory — generation-unbound retained grant in matched-endpoint-authz

**Component:** `matched-endpoint-authz` (extracted `SoftwareClient` from the
SP27 matched-handoff endpoint adapter)
**CWE:** CWE-863 Incorrect Authorization
**Severity:** not scored (research artifact; no production deployment)
**Status:** fixed reference available (see S1 control in `harness.py`)

## Affected

- `matched-endpoint-authz` version `< 0.2.0` (the original `SoftwareClient`
  semantics; SHA-256 `cac2619a1b0c7542e85e56e9438120e8ff6c12cd3eeac1f740c5c75673bc6b20`
  identifies the exact source snapshot).
- The equivalent ledger in the SP27 research project.

## Summary

The authorization ledger keys grants only by `(subject, object)` and does not
bind a grant to an object generation. `reuse` deletes use records and advances
the object generation, but leaves the old grant intact. A subject that retains a
read grant from an earlier generation can then perform an ordinary `acquire`
naming the current generation; `acquire` verifies only that the requested
generation is current, accepts the generation-unbound grant, and mints a fresh
current-generation handle. That handle authorizes reads of the successor
generation's state.

## Impact

A subject whose read authorization should have expired at reuse can read the
successor generation's data without re-grant. The defect violates the intended
invariant that reuse atomically clears all grants on the object.

## Root cause

`rights` is keyed by `(subject, object)` with no generation field, and `reuse`
does not remove `rights[(subject, object)]` entries for the reused object.

## Fix

Clear all grants on the object within the same transition that advances its
generation (see the `S1` scenario in `harness.py`, or the RTL-enforced B15 arm
in the SP27 project). A subject admitted to an earlier incarnation holds no
right on the next until readmitted.

## References

- This advisory (`SECURITY.md`)
- `README.md` and `harness.py` in this repository
