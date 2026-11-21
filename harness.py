"""Deterministic, GPU-free reproduction of the SP27 generation-unbound grant.

Run:  python3 harness.py

Scenario (S0, original / vulnerable):
  1. Subject A is granted READ on object 0.
  2. A acquires a handle on the current generation -> OK.
  3. Owner O (with reclaim/execute right) sanitizes object 0 and reuses it,
     advancing generation 0 -> 1. Reuse clears uses but NOT A's grant.
  4. A acquires again naming the current generation (1). Because the
     generation-unbound grant still exists, acquire returns a fresh handle.
  5. A issues an access through that handle -> a read of the successor
     generation is authorized.

Scenario (S1, repair control):
  Same steps, but reuse also clears every grant on the object. A's second
  acquire is DENIED, matching the fix described in the advisory.
"""

from matched_endpoint_authz import SoftwareClient, OK, DENY, STALE, WAIT, R, W, X

A, O = 1, 9   # subject A (reader), subject O (owner with reclaim right)


def sanitize_and_reuse(client, obj):
    """Drive the normal (non-weak) reuse path: grant reclaim -> sanitize -> reuse."""
    client.grant(O, obj, X)
    sz = client.step(m_valid=1, m_op=8, m_subj=O, m_obj=obj, m_ogen=client.ogen[obj],
                     m_epoch=0)
    assert sz["status"] == OK, f"sanitize descriptor: {sz}"
    client.step(e_san_valid=1, e_san_obj=obj, e_san_tok=sz["tok"], e_san_epoch=0)
    ru = client.step(m_valid=1, m_op=4, m_subj=O, m_obj=obj, m_ogen=client.ogen[obj],
                     m_epoch=0)
    assert ru["status"] == OK, f"reuse: {ru}"
    return ru


def run_s0():
    c = SoftwareClient()
    obj = 0

    # 1. grant A read on object 0
    c.grant(A, obj, R)

    # 2. A acquires on current generation
    a1 = c.step(m_valid=1, m_op=1, m_subj=A, m_obj=obj, m_ogen=c.ogen[obj],
                m_rights=R, m_epoch=0)
    assert a1["status"] == OK, f"A acquire (gen0): {a1}"

    # 2b. A finishes and closes the use; the grant outlives the use
    c.step(m_valid=1, m_op=3, m_subj=A, m_slot=a1["slot"], m_gen=a1["gen"],
           m_epoch=0)

    # 3. owner reuses object -> generation advances, A's grant survives
    sanitize_and_reuse(c, obj)
    assert c.ogen[obj] == 1
    assert c._current_right(A, obj) == R, "A's grant was unexpectedly cleared"

    # 4. A acquires again naming the CURRENT generation -> OK (the defect)
    a2 = c.step(m_valid=1, m_op=1, m_subj=A, m_obj=obj, m_ogen=c.ogen[obj],
                m_rights=R, m_epoch=0)
    assert a2["status"] == OK, f"A re-acquire (gen1) should be OK: {a2}"

    # 5. A issues an access -> read authorized on successor generation
    acc = c.step(m_valid=1, m_op=2, m_subj=A, m_slot=a2["slot"], m_gen=a2["gen"],
                 m_rights=R, m_epoch=0)
    assert acc["status"] == OK and acc["issue"] == 1, f"A access should issue: {acc}"

    print("[S0] VULNERABLE reproduced: A re-acquired after reuse and issued a read "
          f"on generation {c.ogen[obj]} with handle [{a2['slot']},{a2['gen']},0,0]")
    return True


class FixedSoftwareClient(SoftwareClient):
    """S1 repair: reuse also clears every grant on the object."""

    def step(self, **kw):
        if kw.get("m_valid") and kw.get("m_op") == 4:
            obj = kw.get("m_obj", 0)
            out = super().step(**kw)
            if out["status"] == OK:
                for (s, o) in [k for k in self.rights if k[1] == obj]:
                    del self.rights[(s, o)]
            return out
        return super().step(**kw)


def run_s1():
    c = FixedSoftwareClient()
    obj = 0
    c.grant(A, obj, R)
    a1 = c.step(m_valid=1, m_op=1, m_subj=A, m_obj=obj, m_ogen=c.ogen[obj],
                m_rights=R, m_epoch=0)
    assert a1["status"] == OK
    c.step(m_valid=1, m_op=3, m_subj=A, m_slot=a1["slot"], m_gen=a1["gen"],
           m_epoch=0)
    sanitize_and_reuse(c, obj)
    assert c.ogen[obj] == 1
    assert c._current_right(A, obj) == 0, "S1 should have cleared A's grant"

    a2 = c.step(m_valid=1, m_op=1, m_subj=A, m_obj=obj, m_ogen=c.ogen[obj],
                m_rights=R, m_epoch=0)
    assert a2["status"] == DENY, f"S1 re-acquire should be DENIED: {a2}"

    print("[S1] REPAIR control: A's re-acquire after reuse is DENIED "
          f"(status={a2['status']})")
    return True


if __name__ == "__main__":
    run_s0()
    run_s1()
    print("ALL CHECKS PASSED")
