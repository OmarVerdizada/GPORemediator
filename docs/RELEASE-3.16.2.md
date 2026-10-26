# 3.16.2 — result context and refresh selection

The gpupdate confirmation dialog previously defaulted to the PDC for computer OU plans. The worker correctly rejected that target, but the recorded operation could become REVIEW_REQUIRED even though the GPO write had succeeded. A service outage could also leave a "changes enabled" header beside a result described as live, with an empty draft target above an older operation result.

- Derive refresh choices from the recorded operation. Domain-account policy offers the PDC; computer and user endpoint plans offer scope computers. A separate draft selection cannot change the operation's target.
- Validate incompatible refresh in the backend before claiming the GPO or replacing its result. The worker independently enforces domain versus endpoint refresh boundaries.
- Display the recorded operation's GPO, target DN, operation ID and check/record time on the verification page. Filter results by the selected GPO and target when a complete selection exists.
- Describe verification as a snapshot. During an outage, evidence is labelled recorded and shown with neutral indicators. Re-verify, refresh, replan, evidence retrieval and mutation confirmation are disabled until reconnection. Copying a saved manual check remains available.
- Show "write status unavailable" during outage/restart rather than repeating a cached write-gate status. The operation and draft steppers use the corresponding context.
- Preserve the distinction between GPO publication, controller replication, endpoint refresh, effective values and winning policy. Offline, unavailable and failed probes do not become verified results.

## Operator follow-up

The footer must report 3.16.2 after installing the complete package. A page still showing 3.16.0 is running older assets. Once the service and delegated session reconnect, open the relevant operation, run read-only verification, and explicitly request **Scope computers** refresh if needed. Use **Access & evidence** for endpoint permissions and RSoP source attribution. A successful DC readiness check does not establish connectivity or authority on each endpoint.

Local validation covers actual result rendering, mixed-target history, recorded timestamps, offline/reconnect navigation and disabled actions, operation-scoped confirmation choices, backend refresh rules, worker refusal before endpoint invocation, and packaged source/runtime fingerprints. Browser tests use recorded HTTP responses; worker tests use directory/transport doubles. Live AD testing in the deployment environment remains necessary.
