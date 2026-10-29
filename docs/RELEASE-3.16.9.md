# 3.16.9 — live checks and target-aware values

The compact sidebar now places its shield and expand button on separate centered rows, with accessible action labels and tooltips. Both controls stay inside the rail.

Verification streams product-owned evidence independently of the final PowerShell response. GPO configuration, direct link, each controller and each endpoint emit checking and measured-result events. The server validates bounded frames, assigns timestamps and persists the latest check per phase/target on the operation. Nested PowerShell function returns remain separate from progress information.

The control screen polls the existing server workflow/history APIs every three seconds and displays queued work, current stages and host results. Previous measurements are hidden while a fresh check is running. Queued jobs are pinned to a snapshot of their GPO/OU selection; switching targets cannot display another OU’s in-flight check. A polling failure is displayed as interrupted live updates; it cannot turn into success. Final unavailable endpoint reasons appear directly in the result. Refresh still requires explicit approval, and verification remains read-only.

Preview distinguishes **stored GPO value** from **current target value**. Non-domain endpoint values are explicitly unmeasured at Preview; an AD domain-account value remains separately measured. A missing, disabled or reprioritized direct link is shown before approval. Missing direct links do not rule out inherited policy, and a link does not identify the winning GPO. A stored value equal to the desired value cannot produce NO_CHANGE when the required direct link is absent.

The unused duplicate remediation context renderer and its private CSS were removed. [Cleanup recommendations](CLEANUP-RECOMMENDATIONS.md) identify further consolidation opportunities and their real dependencies; functional reporting, access diagnostics, FGPP, workflow and audit features remain available.

Tests use local HTTP fixtures and mocked directory/endpoint APIs. They exercise asynchronous state transitions, interrupted polling, actual unavailability, a matching stored value with no target link, information-stream separation, progress validation, compact navigation and mobile layout. They do not certify a live deployment domain or endpoint connectivity.
