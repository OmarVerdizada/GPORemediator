$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$node = Get-Command node.exe,node -ErrorAction SilentlyContinue | Select-Object -First 1
if (!$node) { throw 'Node.js 22+ is required only for browser regression tests.' }
$npm = Get-Command npm.cmd,npm -ErrorAction SilentlyContinue | Select-Object -First 1
if (!$npm) { throw 'npm is required to install the optional Playwright browser-test dependency.' }
& $npm.Source install --ignore-scripts --no-audit --no-fund
if ($LASTEXITCODE -ne 0) { throw 'Frontend test dependency installation failed. Production build itself does not depend on Node/npm.' }
Write-Host 'Frontend browser test dependency installed.' -ForegroundColor Green
