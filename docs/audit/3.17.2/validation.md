# 3.17.2 validation

The complete audit passed all 65 command-level checks with zero failures.

The command-level results and log hashes are retained in `test-results.json`. The final portable build supersedes the initial build after a visual refinement that keeps long target DNs inside their plan cells. Full logs are under `work/audit/3.17.2/`; screenshots are under `work/screens/3.17.2/`.

`Test-PowerShellTransport.ps1` launches a real Windows PowerShell 5.1 child process and runs the production bootstrap. Session and Invoke-Command are replaced with local stubs, so the worker text is read but no remoting or AD command executes. The success fixture emits a stage, dictionary-shaped InformationRecord evidence and module stdout without a trailing newline, followed by the actual bootstrap result. The legacy whole-stdout JSON parser rejects this fixture; the framed result remains valid and carries the expected SID read-back. The failure fixture retains its failed response. Each has exactly one result frame and neither emits the fixture credential.

The C# workspace regression uses the actual streaming reader to accept framed results among module stdout, preserve failure responses, reject duplicate final frames and retain existing progress/output bounds. Error-stream checks distinguish signing/policy, parse and unclassified failures while returning only product-owned classifications and validated exit/stage/length metadata. Private stderr text never appears in the exposed error. Generated GPO launcher isolation, asset integrity, identity/CSRF gates and the existing workflow/recovery regressions remain covered.

Reviewed controls accept a one-character note through real C# validation. Browser recovery tests submit two-character notes for all eleven reviewed controls. Blank/whitespace notes and unapproved policy fields remain blocked. Standalone manual procedure generation uses the same nonempty review boundary. The 2048-character limit remains.

Browser fixtures verify that the primary plan comparison displays the stored value and source GPO name/ID, including the equal-value but missing-link case. Absent settings say **Not configured in selected GPO**, and failed result read-back says **Read unavailable**. Endpoint measurements, link state and winning-policy attribution remain distinct. Both themes and mobile layouts, long target-DN bounds, live checking, offline evidence and no unintended operation submission remain covered.

Mapping and endpoint tests cover all 405 catalog controls, with 394 automated and eleven reviewed controls. The worker-chain fixtures cover the shared handlers, all eight domain-account properties, reviewed explicit values, publication, refresh, rollback and verification. They use private filesystem fixtures and mocked directory APIs. The 413-scenario full writer matrix recorded for 3.17.1 was not rerun for this transport/UI release and is not presented as a 3.17.2 test result.

No live deployment AD, GPO or endpoint was modified. The reported transport-error class is reproduced locally, but the user's management-host stdout/stderr was not provided, so this does not establish which extra output or process failure occurred there.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Invoke-FullAuditTests.ps1 -OutputDirectory work/audit/3.17.2/reproduce
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/Test-PowerShellTransport.ps1
node scripts/Test-ReviewedTargetUi.cjs
node scripts/Test-LivePolicyUi.cjs
```
