# Domain account control targeting correction (2026-10-20)

The Password history form previously presented a domain account control as ordinary Computer Configuration, then failed only after a pilot GPO was submitted. The form now labels domain account policy explicitly and explains the required Default Domain Policy/domain-root combination.

The subsequent [target access update](TARGET-ACCESS-2026-10-20.md) keeps all discovered GPOs and OUs visible. Selecting an incompatible object shows a compatibility message; missing edit/link/SYSVOL rights are a separate permission error with delegation guidance. The required Default Domain Policy is never selected silently.

Domain forms offer the normal cycle or PDC refresh and preserve existing link order. Computer and user forms retain their own OU targeting. Invalid restored targets invalidate the active preview/approval. Typed backend validation rejects an incompatible domain-account GPO before DC execution; the DC worker independently rechecks it.

Offline form, server and browser fixtures cover the reported mismatch. Live AD writes and delegation have not been validated.
