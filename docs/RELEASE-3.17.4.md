# GPO Remediator 3.17.4

New remediation previews pin the selected policy fields, including the initial recommendations. A requested 15 is no longer considered applied merely because the actual value 30 meets a benchmark minimum of 15. The same normalization covers registry, security-template and exact audit settings. Benchmark scans keep threshold semantics. Required-inclusion rules retain additional deny assignments or audit flags unless explicitly overridden.

Domain-account verification uses exact equality independently of the stored GPO file. Legacy records that claimed success for AD 30/requested 15 render as mismatches. Apply of an old unpinned plan requires a fresh preview; Re-verify reads state and never retries the write.

Results show checked direct-link enablement and priority. A matching stored value without a required enabled link is not NO_CHANGE. Source GPO names identify stored configuration; endpoint value evidence and winning-policy attribution remain separate.

Windows file commits now retry transient sharing/lock failures within a bounded interval. ReplaceFile error 1175 uses the existing durable write path after retries, as does access denied under delegated GPMC write permissions. Persistent sharing and disk failures retain the original file and fail the operation. Private filesystem fault-injection tests cover these outcomes.

Lockout dependency validation runs before writes and before snapshot import. In the reported duration=30/window=30/threshold=0 state, selecting duration 15 requires explicitly changing 1.2.4 (reset-counter window) to a compatible value first, then creating a fresh 1.2.1 duration plan. No related policy changes automatically. Threshold zero remains zero and the interface explains that lockout is disabled. See the [AD cmdlet parameter constraints](https://learn.microsoft.com/en-us/powershell/module/activedirectory/set-addefaultdomainpasswordpolicy?view=windowsserver2025-ps).

Validation covers all 405 controls across 413 local/domain scope cases with the actual worker and private filesystem fixtures. Directory, GPMC and endpoint APIs are mocked. The complete local audit also covers transport, authorization, endpoint evidence, refresh, rollback, frontend rendering and packaging. Detailed final results are retained in `docs/audit/3.17.4`. These checks do not establish success on prosol.local; live AD is unavailable in this checkout.
