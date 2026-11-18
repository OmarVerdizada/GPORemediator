$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$repo=Split-Path $PSScriptRoot -Parent
function Check($condition,[string]$name){if(!$condition){throw $name};Write-Output ('PASS '+$name)}
$installer=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Install-MachineService.ps1') -Raw
$starter=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Start-ControlPanel.ps1') -Raw
$program=Get-Content -LiteralPath (Join-Path $repo 'backend\Program.cs') -Raw
$store=Get-Content -LiteralPath (Join-Path $repo 'backend\Infrastructure\Store.cs') -Raw
$control=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Start-MachineControlCenter.ps1') -Raw
$panel=Get-Content -LiteralPath (Join-Path $repo 'Control-Panel.ps1') -Raw

Check ($installer -match "New-ScheduledTaskPrincipal\s+-UserId 'SYSTEM'\s+-LogonType ServiceAccount\s+-RunLevel Highest") 'machine backend uses the stable LocalSystem service identity'
Check ($installer -match 'New-ScheduledTaskTrigger\s+-AtStartup') 'machine backend starts with Windows'
Check ($installer -match 'MultipleInstances IgnoreNew') 'a second backend instance is rejected'
Check ($installer -match '/api/v1/health/live') 'installation waits for actual backend health'
Check ($installer -match "payload\.status -ceq 'live'" -and $installer -match "payload\.apiVersion -ceq '1\.0'") 'health probe validates the GPO Remediator API contract'
Check ($installer -match 'DataProtectionScope\]::CurrentUser' -and $installer -match 'DataProtectionScope\]::LocalMachine') 'legacy audit key migration is explicit and preserves the database'
Check ($installer -match '\[Array\]::Clear' -and $installer -notmatch 'CryptographicOperations') 'sensitive byte cleanup is compatible with Windows PowerShell 5.1'
Check ($installer -match 'PRESERVE_AND_INITIALIZE' -and $installer -match 'GpoRemediator\.LegacyState-' -and $installer -match 'Move-Item -LiteralPath \$stateRoot') 'foreign DPAPI recovery requires explicit confirmation and preserves the exact state root'
Check ($installer -notmatch 'Remove-Item -LiteralPath \$stateRoot') 'foreign DPAPI recovery never deletes the legacy state root'
Check ($program -match 'ProtectKeysWithDpapi\(true\)') 'ASP.NET server keys use machine DPAPI'
Check ($store -notmatch 'DataProtectionScope\.CurrentUser' -and $store -match 'DataProtectionScope\.LocalMachine') 'audit integrity key is no longer tied to an interactive session'
$probe=$starter.IndexOf('Get-RemediatorLoopbackService',[StringComparison]::Ordinal)
$stateWrite=$starter.IndexOf('New-Item -ItemType Directory -Path $workRoot',[StringComparison]::Ordinal)
Check ($probe -ge 0 -and $stateWrite -gt $probe) 'interactive launcher opens a healthy shared service before touching ProgramData'
Check ($starter -match 'MACHINE_SERVICE_OFFLINE' -and $starter -match 'must not create a second backend') 'offline shared service fails safely instead of launching a competing session backend'
Check ($control -match 'WindowsBuiltInRole\]::Administrator' -and $control -match '-Verb RunAs' -and $control -match 'Control-Panel\.ps1') 'visible machine Control Center elevates explicitly and reuses the lifecycle UI'
Check ($panel -match 'Start-ScheduledTask -TaskName \$machineTaskName' -and $panel -match 'Machine-service runtime repair') 'machine Control Center starts the SYSTEM task and never falls back to a user-owned backend'
Check ($starter -match 'Control-Panel\.ps1' -and $starter -match '-MachineClient') 'primary launcher restores the original visual Control Center for a healthy machine backend'
Check ($panel -match 'Get-RemediatorLoopbackService' -and $panel -match 'Invoke-RemediatorLoopbackAction' -and $panel -match 'if\(\$MachineClient\)') 'standard-user Control Center reads lifecycle state through authenticated loopback APIs without ProgramData access'
Check ($starter -match 'MACHINE_SERVICE_REQUIRED' -and $starter -match 'WindowsBuiltInRole\]::Administrator' -and $starter.IndexOf('MACHINE_SERVICE_REQUIRED',[StringComparison]::Ordinal) -lt $stateWrite) 'standard operators never fall through to legacy ProgramData startup'
Check ((Get-Content -LiteralPath (Join-Path $PSScriptRoot 'LoopbackLifecycle.ps1') -Raw) -match '/api/v1/health/ready' -and (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'LoopbackLifecycle.ps1') -Raw) -notmatch "Invoke-RestMethod[^\r\n]+/api/service'") 'native launcher readiness does not depend on browser confirmation cookies'
Check (!(Test-Path -LiteralPath (Join-Path $repo 'GpoRemediator-ControlCenter.cmd'))) 'duplicate top-level Control Center launcher is retired'
Write-Output 'PASS machine-service contract: one backend, many authenticated Windows sessions.'
