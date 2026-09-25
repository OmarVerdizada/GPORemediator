param([switch]$SmokeTest)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path $PSScriptRoot -Parent
$workRoot=Join-Path $projectRoot 'work'
try {
    New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
    $panel=Join-Path $projectRoot 'Control-Panel.ps1'
    if (!(Test-Path -LiteralPath $panel)) { throw 'Control-Panel.ps1 is missing. Extract the complete project archive before starting.' }
    & $panel -SmokeTest:$SmokeTest
    exit 0
} catch {
    $details=('[{0}] Control panel startup failed: {1}{2}{3}' -f (Get-Date -Format 's'),$_.Exception.Message,[Environment]::NewLine,$_.ScriptStackTrace)
    try { Add-Content -LiteralPath (Join-Path $workRoot 'panel-error.log') -Value $details -Encoding UTF8 } catch { }
    [Console]::Error.WriteLine($details)
    exit 1
}
