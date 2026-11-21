"""matched_endpoint_authz — standalone extraction of the SP27 SoftwareClient ledger.

This module is a faithful, dependency-free (stdlib-only) extraction of the
``SoftwareClient`` class from the SP27 matched-handoff endpoint adapter
``matched_endpoint.py`` (SHA-256
``cac2619a1b0c7542e85e56e9438120e8ff6c12cd3eeac1f740c5c75673bc6b20``).

What is kept: the rights/use/generation decision logic (acquire, access, close,
retire, sanitize-descriptor, reuse, and the read-only ``force_reuse`` used by the
``Cread`` arm). The device endpoint, CUDA event plumbing, queue and observer
socket are removed so the disclosed behavior can be reproduced without a GPU.

What is *not* changed: the semantics that constitute the vulnerability. Grants
are keyed only by ``(subject, object)`` with no object generation. ``reuse``
advances the object generation and clears ``uses`` but leaves ``rights`` intact.
A subject that still holds an old-generation read right can therefore acquire a
fresh current-generation handle after reuse.

WARNING: this is the ORIGINAL (vulnerable) implementation, published strictly as
a reproducible reference for the advisory in SECURITY.md. It must not be used as
a production authorization component. The corrected (S1) behavior is shown in
``harness.py``.
"""

OK, DENY, STALE, WAIT = 0, 1, 2, 3
R, W, X = 1, 2, 4
NBLK, NUSE = 8, 8


def _reply(**kw):
    r = dict(status=OK, valid=0, slot=0, gen=0, epoch=0, issue=0,
             tag=(0, 0, 0), x_obj=0, x_write=0, x_ogen=0, fire=0,
             effect=0, sz=0, sz_obj=0, tok=0, sz_epoch=0, sz_ogen=0,
             g_epoch=0)
    r.update(kw)
    return r


class SoftwareClient:
    """Independent generation-handle ledger (original, unpatched semantics)."""

    def __init__(self):
        self.epoch = 0
        self.decisions = 0
        self.ogen = [0] * NBLK
        self.rights = {}            # keyed by (subject, object) -- NO generation
        self.uses = {}              # keyed by (slot, generation)
        self.inflight = {}
        self.next_slot = 0
        self.next_ugen = 1
        self.next_tag = 1
        self.next_token = 1
        self.sanitized = set()

    def _current_right(self, subj, obj):
        return self.rights.get((subj, obj), 0)

    def _use(self, subj, slot, gen):
        u = self.uses.get((slot, gen))
        if u is None or u["subj"] != subj:
            return None
        return u

    def grant(self, subj, obj, rights):
        """Convenience wrapper for the p_valid grant path (op == p_valid)."""
        self.decisions += 1
        self.rights[(subj, obj)] = rights
        if rights & 3 == 0:
            for u in self.uses.values():
                if u["subj"] == subj and u["obj"] == obj and u["state"] == "issued":
                    u["state"] = "closed"
        return _reply()

    def step(self, **kw):
        self.decisions += 1
        if kw.get("p_valid"):
            s, o, rights = kw.get("p_subj", 0), kw.get("p_obj", 0), kw.get("p_rights", 0)
            self.rights[(s, o)] = rights
            if rights & 3 == 0:
                for u in self.uses.values():
                    if u["subj"] == s and u["obj"] == o and u["state"] == "issued":
                        u["state"] = "closed"
            return _reply()
        if kw.get("e_done_valid"):
            tag = (kw.get("e_done_tag", 0), kw.get("e_done_tep", 0), kw.get("e_done_epoch", 0))
            self.inflight.pop(tag, None)
            return _reply()
        if kw.get("e_san_valid"):
            self.sanitized.add((kw.get("e_san_obj", 0), kw.get("e_san_tok", 0),
                                kw.get("e_san_epoch", 0)))
            return _reply()
        if not kw.get("m_valid"):
            return _reply()

        op, subj = kw.get("m_op", 0), kw.get("m_subj", 0)
        slot, gen = kw.get("m_slot", 0), kw.get("m_gen", 0)
        obj, ogen = kw.get("m_obj", 0), kw.get("m_ogen", 0)
        epoch = kw.get("m_epoch", self.epoch)
        if epoch != self.epoch:
            return _reply(valid=1, status=STALE, epoch=self.epoch)

        if op == 1:  # acquire
            if obj >= NBLK or ogen != self.ogen[obj]:
                return _reply(valid=1, status=STALE, epoch=self.epoch)
            need = kw.get("m_rights", 0) & 3
            if not need or (self._current_right(subj, obj) & need) != need:
                return _reply(valid=1, status=DENY, epoch=self.epoch)
            slot = self.next_slot % NUSE
            self.next_slot += 1
            ugen = self.next_ugen
            self.next_ugen += 1
            self.uses[(slot, ugen)] = dict(subj=subj, obj=obj, ogen=ogen,
                                           rights=need, state="issued", epoch=epoch)
            return _reply(valid=1, status=OK, slot=slot, gen=ugen, epoch=epoch)

        if op == 2:  # access
            u = self._use(subj, slot, gen)
            if u is None or u["ogen"] != self.ogen[u["obj"]] or u["epoch"] != self.epoch:
                return _reply(valid=1, status=STALE, epoch=self.epoch)
            if u["state"] != "issued":
                return _reply(valid=1, status=DENY, epoch=self.epoch)
            need = kw.get("m_rights", 0) & 3
            if not need or not (u["rights"] & need) or not (self._current_right(subj, u["obj"]) & need):
                return _reply(valid=1, status=DENY, epoch=self.epoch)
            tag = self.next_tag
            self.next_tag += 1
            full_tag = (tag, u["obj"], self.epoch)
            self.inflight[full_tag] = (slot, gen)
            return _reply(valid=1, status=OK, issue=1, tag=full_tag,
                          x_obj=u["obj"], x_write=int(need == W), x_ogen=u["ogen"], epoch=self.epoch)

        if op == 3:  # close
            u = self._use(subj, slot, gen)
            if u is None or u["epoch"] != self.epoch:
                return _reply(valid=1, status=STALE, epoch=self.epoch)
            u["state"] = "closed"
            return _reply(valid=1, status=OK, epoch=self.epoch)

        if op == 7:  # retire
            u = self._use(subj, slot, gen)
            if u is None:
                return _reply(valid=1, status=STALE, epoch=self.epoch)
            if any(use == (slot, gen) for use in self.inflight.values()):
                return _reply(valid=1, status=WAIT, epoch=self.epoch)
            del self.uses[(slot, gen)]
            return _reply(valid=1, status=OK, epoch=self.epoch)

        if op == 8:  # sanitize descriptor
            if obj >= NBLK or ogen != self.ogen[obj]:
                return _reply(valid=1, status=STALE, epoch=self.epoch)
            if not (self._current_right(subj, obj) & X):
                return _reply(valid=1, status=DENY, epoch=self.epoch)
            if any(u["obj"] == obj and u["ogen"] == ogen and u["state"] == "issued"
                   for u in self.uses.values()):
                return _reply(valid=1, status=WAIT, epoch=self.epoch)
            if any(tag[1] == obj for tag in self.inflight):
                return _reply(valid=1, status=WAIT, epoch=self.epoch)
            token = self.next_token
            self.next_token += 1
            return _reply(valid=1, status=OK, sz=1, sz_obj=obj, tok=token,
                          sz_epoch=self.epoch, sz_ogen=ogen, epoch=self.epoch)

        if op == 4:  # reuse after actual sanitization
            if obj >= NBLK or ogen != self.ogen[obj]:
                return _reply(valid=1, status=STALE, epoch=self.epoch)
            if not (self._current_right(subj, obj) & X):
                return _reply(valid=1, status=DENY, epoch=self.epoch)
            if any(u["obj"] == obj and u["ogen"] == ogen and u["state"] == "issued"
                   for u in self.uses.values()):
                return _reply(valid=1, status=WAIT, epoch=self.epoch)
            if any(tag[1] == obj for tag in self.inflight):
                return _reply(valid=1, status=WAIT, epoch=self.epoch)
            if not any(o == obj for o, _, _ in self.sanitized):
                return _reply(valid=1, status=WAIT, epoch=self.epoch)
            for key in [k for k, u in self.uses.items() if u["obj"] == obj]:
                del self.uses[key]
            self.ogen[obj] += 1
            self.sanitized = {x for x in self.sanitized if x[0] != obj}
            # NOTE: rights[(subj, obj)] is NOT cleared here -- this is the defect.
            return _reply(valid=1, status=OK, gen=self.ogen[obj], epoch=self.epoch)

        return _reply(valid=1, status=DENY, epoch=self.epoch)

    def force_reuse(self, obj):
        """Cread-only path: omit the event fence and sanitize fact (kept for parity)."""
        for key in [k for k, u in self.uses.items() if u["obj"] == obj]:
            del self.uses[key]
        self.ogen[obj] += 1
        return self.ogen[obj]
