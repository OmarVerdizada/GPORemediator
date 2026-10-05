param([ValidateRange(1024,65535)][int]$Port = 5080, [switch]$SmokeTest)
# Start-Process can inherit PowerShell 7 module paths. Resolve Windows modules first.
$windowsModules = [IO.Path]::Combine($env:SystemRoot, 'System32\WindowsPowerShell\v1.0\Modules')
$env:PSModulePath = $windowsModules + ';' + $env:PSModulePath
$ErrorActionPreference='Stop'
$projectRoot=Split-Path $PSScriptRoot -Parent
$workRoot=Join-Path $env:ProgramData 'GpoRemediator\State'
try {
    New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
    $panel=Join-Path $projectRoot 'Control-Panel.ps1'
    if (!(Test-Path -LiteralPath $panel)) { throw 'Control-Panel.ps1 is missing. Extract the complete project archive before starting.' }
    & $panel -Port $Port -SmokeTest:$SmokeTest
    exit 0
} catch {
    $details=('[{0}] Control panel startup failed: {1}{2}{3}' -f (Get-Date -Format 's'),$_.Exception.Message,[Environment]::NewLine,$_.ScriptStackTrace)
    $diagnosticPath=Join-Path $workRoot 'panel-error.log'
    try { Add-Content -LiteralPath $diagnosticPath -Value $details -Encoding UTF8 } catch {
        try {
            $fallback=Join-Path $env:LOCALAPPDATA 'GpoRemediator\Diagnostics'
            New-Item -ItemType Directory -Path $fallback -Force | Out-Null
            $diagnosticPath=Join-Path $fallback 'panel-error.log'
            Add-Content -LiteralPath $diagnosticPath -Value $details -Encoding UTF8
        } catch { $diagnosticPath='Log file could not be written. See the startup console.' }
    }
    [Console]::Error.WriteLine($details)
    try {
        Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
        [System.Windows.MessageBox]::Show(
            "GPO Remediator Control Center could not start.`n`n$($_.Exception.Message)`n`nFull details were written to:`n$diagnosticPath",
            'GPO Remediator - Startup Error',
            [System.Windows.MessageBoxButton]::OK,
            [System.Windows.MessageBoxImage]::Error
        ) | Out-Null
    } catch { }
    exit 1
}
