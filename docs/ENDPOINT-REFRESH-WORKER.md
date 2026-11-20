# Endpoint policy refresh

## Computer refresh at startup without a queue

For computers that should process all applicable Computer GPOs at each startup, deploy `scripts/Install-ComputerStartupRefresh.ps1` once on each intended domain member using local administrator rights or your endpoint management system. The operator can then choose **Wait for normal cycle** during remediation. This deployment works without a queue share, a worker certificate or an inbound endpoint connection.

The installer registers **GPO Remediator - Computer policy at startup** with one boot trigger. Windows launches its own `gpupdate.exe /target:computer /force /wait:-1` under SYSTEM one minute after boot. Task Scheduler can delay execution if the machine is busy. A failed task can retry three times at five-minute intervals. The policy source must be reachable for new settings to arrive. Scope this deployment to member workstations or member servers. Repeated installer runs check the existing task.

After reboot, use `Get-ScheduledTaskInfo -TaskName 'GPO Remediator - Computer policy at startup' | Select-Object LastRunTime,LastTaskResult` on the endpoint. A new run time and exit code 0 record successful command execution. Use Re-verify to inspect the effective policy. The management UI cannot predict a future boot time.

## Refresh after an approved Apply

Select **Refresh scope computers** for a Computer GPO or **Refresh user policy on scope endpoints** for a User GPO. The workflow starts refresh after successful publication. The optional worker picks up a queued request when its domain member is online. Requests expire after 24 hours. The verification screen shows an estimated time for the next pickup when the worker has reported one. Re-verify updates the estimate and reads the receipt.

## Provision the pilot

1. Choose a dedicated member-server SMB share with Kerberos access and SMB signing. Use a server DNS name in the UNC path. Under the share, provision `<endpoint-fqdn>\requests` and `<endpoint-fqdn>\results` for every enrolled member endpoint. Configure both share permissions and NTFS ACLs. The management backend's identity needs write access to the request folders and read access to the results. Give each endpoint computer account read access to only its own request folder and modify access to only its own result folder. Protect the parent directories and inheritance. Keep task, code and folder-administration rights separate from GPO operators.
2. Provision a dedicated RSA certificate in the management host's Local Computer Personal store. The backend identity needs access to its private key. Copy only the public certificate and the verified `scripts/Invoke-EndpointRefreshWorker.ps1` to an administrator-protected local directory on each pilot computer.
3. On pilot member computers, register a task under LocalSystem to run the worker at startup and periodically. A one-minute period is suitable for a small pilot. Use the full local script and certificate paths. Set the task to ignore a new instance while one is active. Restrict task and file modification to authorized administrators. Use the organization's PowerShell signing policy. Pass the share path to `-QueueRoot` and the pinned public certificate path to `-PublisherCertificatePath`.
4. Set `Windows__EndpointQueueRoot` and `Windows__EndpointQueueCertificateThumbprint` in the management backend's approved service environment and restart it. Keep the feature disabled by leaving the queue root unset until the share ACLs, certificate access and endpoint task have been reviewed. Never place the private key, credentials or the worker script in an operator-writable directory.
5. Approve a refresh for one pilot member computer. Test one request with the endpoint online and one with it offline. On boot, the worker will pick up unexpired requests. Re-verify to retrieve the receipt. A completed receipt reports the exit of `gpupdate`. Confirm effective values independently.

Keep each receipt at least until its corresponding request expires. The receipt is also the claim that prevents repeated execution. If a worker was interrupted after claiming a request, inspect the endpoint before issuing a new approved request.

## Enable signed endpoint value evidence

1. Deploy the same release of the worker, `backend/PowerShell/GpoWorkflow.Worker.ps1`, and `backend/data/gpo-production-mappings.json` beneath one administrator-protected tree, preserving the relative folders. The installed catalog fixes the authorized policy fields.
2. Give each enrolled computer its own RSA evidence-signing certificate in the Local Computer Personal store and grant the task identity access to its private key. Pass its thumbprint as `-ReceiptCertificateThumbprint`. Import the public certificate on the management host in Local Computer Trusted People.
3. Add the endpoint FQDN and its certificate thumbprint to the backend's `Windows:EndpointQueueReceiptThumbprints` configuration map. Restart the backend after enrollment. Verification mode requires both the queue root and at least one pinned endpoint certificate. Unenrolled endpoints are reported as unavailable in this mode.
4. Select **Re-verify**. The backend checks the GPO, link and pinned scope, then queues a read-only check. The first result may be pending. Select **Re-verify** after the worker check-in to collect the signed evidence. Check requests expire after five minutes. For a User GPO, set an endpoint OU and an enabled verification user in the plan. The selected user's profile hive must be loaded for HKCU evidence.

To report the upcoming Task Scheduler run, pass the registered worker task's name using `-TaskName` and its folder using `-TaskPath` (default root). Otherwise the worker estimates pickup from the interval between recent check-ins. An offline member can collect an unexpired request on boot. An overdue estimate remains pending until the endpoint acknowledges it.

For queued user refresh, install the Windows GroupPolicy module on the enrolled endpoint and select the OU containing the affected session computers. The worker waits for a signed-in session, then calls the local `Invoke-GPUpdate -Target User -Force -RandomDelayInMinutes 0`. The receipt records Windows accepting the user task. No restart or sign-out is requested.

The evidence worker supports the installed computer registry, LSA/security-policy, firewall and advanced-audit probes and the selected user's HKCU probe. Measurements apply to the endpoint sample. RSoP and winning GPO attribution remain separate. Domain controllers use manual refresh and manual endpoint evidence in worker mode.
