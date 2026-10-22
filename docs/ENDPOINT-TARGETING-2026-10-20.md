# Automatic OU endpoint targeting (2026-10-20)

Settings now offers Endpoint targets with two choices:

- **Selected OU automatically**: discover enabled computer accounts in the selected OU and child OUs. No per-host text entry is required. Computer policy uses the selected policy OU. User policy uses the separately selected endpoint/computer OU, not the user OU. Domain account policy may use the PDC strategy as before.
- **Explicit host list**: keep only in-scope computers whose exact DNS names are in the configured list. Each line contains one FQDN. This is useful for a small pilot. An empty list in this mode selects no endpoints.

New configurations with no host list default to automatic mode. Existing nonempty lists default to explicit mode, so upgrading does not silently expand remote execution. Choose automatic mode and save/restart to stop using an old DC-only host list. The manual host textarea is disabled in automatic mode, and saves clear the unused list. The mode participates in the plan configuration hash; changing it requires a fresh preview.

A 200-computer OU is supported by the resolver. The previous 100-computer refresh enumeration limit is now a 5,000-computer bound, consistent with the existing preview inventory bound. The query uses subtree search and enabled computer accounts. It does not scan the network. Records without valid in-domain DNS names are excluded. More than 5,000 returned accounts require a narrower OU rather than silent truncation. Explicitly configured host lists still have their separate 100-entry limit.

GPO publication, remote refresh and endpoint verification remain distinct. Apply writes the GPO; it does not implicitly run gpupdate. An explicitly confirmed Scope refresh schedules gpupdate for the current discovered targets and records per-host results. Large or unreachable scopes may take longer and remain subject to the operation deadline. Scheduling a task does not prove that the endpoint has processed policy. Verification still samples at most five eligible endpoints and does not establish OU-wide compliance. Domain/endpoint permissions continue to be enforced by Windows using the delegated execution account.

## The two DC fields in the screenshots

The main **Writable DC FQDN** field is required. It pins the writable domain controller used for inventory, previews and GPO operations. Leaving it blank fails configuration validation; it does not mean "choose any DC". Use **Auto-detect** to attempt discovery, then review the filled name. The selected DC must be writable and accessible with the required modules and services.

A DC name typed in **Endpoint hosts**, on the other hand, is just an endpoint restriction. It does not select the GPO server and does not represent all domain computers. In automatic OU mode this text is unnecessary and cleared. Only computers in the chosen scope are candidates; the configured DC is not automatically added as a workstation refresh target.

## Validation

The production PowerShell resolver is exercised against 200 synthetic AD computer records, independent user/endpoint OUs, PDC/None strategies, invalid and foreign hostnames, explicit mode, legacy mode inference, invalid modes and the 5,000-object boundary. Settings browser fixtures exercise legacy display, mode toggling, disabled manual entry, both save payloads and the required DC field. Existing mapping and endpoint fixtures are synthetic, not live AD enforcement evidence. No production GPO or endpoint was modified during development.
