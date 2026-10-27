# 3.16.5 — user-session refresh and workflow submission

Explicit refresh workflows now use the top-level refresh target consistently during service preflight, queue persistence and execution. Previously, the browser supplied that target correctly but the first service validation read an unset field in the nested consent. This could reject a valid request with “Choose PDC or scope computers” before any endpoint command ran. The server normalizes consent from the authoritative workflow target, including when nested consent disagrees.

User-policy results now offer **Run gpupdate /target:user /force** with **User sessions on endpoint OU computers**. A recorded plan without a session endpoint OU disables remote refresh and explains that a fresh plan must include one. Submission also rejects that missing scope before queueing. The PDC remains incompatible with user-session refresh. The optional verification user remains optional for OU-wide GPO publication and remote user refresh.

The worker uses **Invoke-GPUpdate -Target User**, which schedules user-policy processing on the pinned session computers. It does not run computer policy under the remoting operator's identity. Scheduling remains SCHEDULED, never proof of completion or effective user settings. A pinned host removed from the live authorized scope is reported as failed without scheduling it. Full-GPO rollback retains its separate existing refresh semantics.

Scope/session placeholders such as `<user-session>` no longer generate impossible wrong-host PowerShell checks or empty Copy buttons. Concrete user endpoint checks clearly identify the intended signed-in user context, or the selected user's loaded profile when an identity was supplied. Standalone manual procedures remain available without recorded endpoint evidence.

See [user policy refresh instructions](USER-POLICY-REFRESH.md). Deploy the complete package and restart through the launcher.

## Validation

Real workflow submission and service validation were exercised with private in-memory records and no running native worker. Valid top-level Scope reaches the queue and normalized consent; PDC and missing user-session endpoint OU are rejected first. Native worker fixtures verify Target User scheduling, failure preservation, no computer-processing fallback and refusal to schedule removed endpoints. Browser fixtures cover missing endpoint guidance, placeholder suppression, Scope-only confirmation, cancellation, the recorded-operation request, correct manual user context and mobile layout. All 405 generated manual commands parse in Windows PowerShell 5.1.

These are isolated tests with mocked directory/endpoint APIs. Live AD, RPC/task scheduling permissions, actual user sessions and resulting HKCU values must be validated in the deployment environment.
