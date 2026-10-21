# Domain account control targeting correction (2026-10-20)

The Password history form previously presented a domain account control as ordinary Computer Configuration, then failed only after an incompatible OU was submitted. The form now labels domain account policy explicitly and requires the domain root.

The subsequent [target access update](TARGET-ACCESS-2026-10-20.md) keeps all discovered GPOs and OUs visible. Any active discovered GPO can carry a domain account policy; the workflow pins it to the domain root at link order 1 so its requested settings are effective. Missing edit/link/SYSVOL rights remain a separate permission error with delegation guidance.

Domain forms offer the normal cycle or PDC refresh and preserve existing link order. Computer and user forms retain their own OU targeting. Invalid restored targets invalidate the active preview/approval. Typed backend validation rejects an incompatible domain-account GPO before DC execution; the DC worker independently rechecks it.

Offline form, server and browser fixtures cover the reported mismatch. Live AD writes and delegation have not been validated.
