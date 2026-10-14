# 3.10.0 — User policy targeting and single sign-in

- Separates the user OU receiving the GPO link from the endpoint OU where user sessions run.
- Requires a concrete in-scope verification user before immediate user-policy refresh.
- Schedules `Invoke-GPUpdate -Target User -Force` only on allowlisted computers in the selected endpoint OU.
- Reads the selected user's loaded `HKEY_USERS\\<SID>` policy values for exact endpoint evidence; unloaded profiles remain pending.
- Removes the PDC choice from user policy refresh because a domain controller is not a user-session target.
- Consolidates credential entry into the single application sign-in screen; settings contain AD environment configuration only.
- Enforces the reviewed catalog contract: 385 computer, 12 user, and 8 domain controls, with HKCU/HKLM scope validation.
