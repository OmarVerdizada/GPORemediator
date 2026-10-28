# 3.16.7 validation

All tests use isolated fixtures or local recorded API responses. No live AD/GPO/endpoint mutation or live enforcement certification was performed.

63/63 command-level checks pass against the final 3.16.7 artifacts, including the final Windows PowerShell 5.1 build and targeted rechecks. The initially stale manual artifact check is retained as an earlier attempt in the results.

## Per-domain control chains

| Domain | Controls | Cases | Result |
| --- | ---: | ---: | --- |
| 1 · Account Policies | 9 | 17 | PASS |
| 2 · Local Policies | 103 | 103 | PASS |
| 3 · Event Log | 0 | 0 | Empty imported heading |
| 4 · Restricted Groups | 0 | 0 | Empty imported heading |
| 5 · System Services | 1 | 1 | PASS |
| 6 · Registry | 0 | 0 | Empty imported heading |
| 7 · File System | 0 | 0 | Empty imported heading |
| 8 · Wired Network (IEEE 802.3) Policies | 0 | 0 | Empty imported heading |
| 9 · Windows Firewall with Advanced Security | 23 | 23 | PASS |
| 10 · Network List Manager Policies | 0 | 0 | Empty imported heading |
| 11 · Wireless Network (IEEE 802.11) Policies | 0 | 0 | Empty imported heading |
| 12 · Public Key Policies | 0 | 0 | Empty imported heading |
| 13 · Software Restriction Policies | 0 | 0 | Empty imported heading |
| 14 · Network Access Protection NAP Client Configuration | 0 | 0 | Empty imported heading |
| 15 · Application Control Policies | 0 | 0 | Empty imported heading |
| 16 · IP Security Policies | 0 | 0 | Empty imported heading |
| 17 · Advanced Audit Policy Configuration | 27 | 27 | PASS |
| 18 · Administrative Templates (Computer) | 230 | 230 | PASS |
| 19 · Administrative Templates (User) | 12 | 12 | PASS |

413 completed chain cases cover all 405 imported controls; the additional eight cases exercise both domain-account and local-account scope. Eleven review-gated controls use explicitly reviewed fixture mappings, not unattended execution. The chain checks preview, backup, writes, selected link, configured-value source, rollback and restored read-back. Dedicated dispatcher fixtures cover user refresh and all 201 rollback targets, including explicit delegated credentials, paging, removed endpoints and scheduling failures.

## False-success regressions

- A successful audit GPO write followed by an unchanged effective audit value finishes with `NEEDS_REVIEW` and retains the mismatch evidence.
- An unreachable verification endpoint finishes with `CHECKS_INCOMPLETE`.
- Apply and Refresh now invoke read-only verification; scheduled convergence checks are retained until the final configured check.
- Audit values that match while subcategory override is absent remain pending with control 2.3.2.1 guidance.
- Per-user audit rows with a shared subcategory GUID cannot supply or overwrite the system policy value.
- Empty GPO values and entirely unconfigured multi-item controls have no source GPO. Explicit zero and empty configured values retain their source.
- Mixed OU selection defaults session endpoints to the selected scope; optional overrides remain available.

## Reproduce

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Invoke-FullAuditTests.ps1 -OutputDirectory work/audit/3.16.7
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Test-RemediationChain.ps1 -AllControls -ReportPath work/audit/all-controls/chain.json
```

The final command-level results are in `test-results.json`; detailed working logs are retained under `work/audit/3.16.7`. The per-control outcomes are in `control-chain-results.json`.
