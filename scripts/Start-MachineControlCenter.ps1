param(
    [string]$ProjectRoot=(Split-Path $PSScriptRoot -Parent),
    [ValidateRange(1024,65535)][int]$Port=5080,
    [switch]$SmokeTest
)
$ErrorActionPreference='Stop'
$rootInput=([string]$ProjectRoot).Trim().Trim('"').TrimEnd('\')
if([string]::IsNullOrWhiteSpace($rootInput)){throw 'MACHINE_CONTROL_CENTER_PATH: Project root is empty.'}
$root=[IO.Path]::GetFullPath($rootInput).TrimEnd('\')
$self=[IO.Path]::GetFullPath($PSCommandPath)
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if(!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
    $powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments='-NoLogo -NoProfile -ExecutionPolicy Bypass -STA -File "{0}" -ProjectRoot "{1}" -Port {2}{3}' -f $self,$root,$Port,$(if($SmokeTest){' -SmokeTest'}else{''})
    Start-Process -FilePath $powershell -ArgumentList $arguments -Verb RunAs -WorkingDirectory $root
    exit 0
}
$panel=Join-Path $root 'Control-Panel.ps1'
if(!(Test-Path -LiteralPath $panel -PathType Leaf)){throw 'MACHINE_CONTROL_CENTER_MISSING: Control-Panel.ps1 is missing from the verified project root.'}
if((Get-Item -LiteralPath $root -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'MACHINE_CONTROL_CENTER_LINK: Project root cannot be a symbolic link or junction.'}
$host.UI.RawUI.WindowTitle='GPO Remediator - Machine Control Center'
Write-Host 'GPO REMEDIATOR - MACHINE CONTROL CENTER' -ForegroundColor Cyan
Write-Host ('Identity: '+$identity.Name)
Write-Host 'This window manages the computer-wide SYSTEM backend. Closing the Control Center does not stop the backend.'
& $panel -Port $Port -SmokeTest:$SmokeTest
if(!$SmokeTest){Write-Host 'Machine Control Center closed. The backend keeps its last selected state.' -ForegroundColor DarkGray}
