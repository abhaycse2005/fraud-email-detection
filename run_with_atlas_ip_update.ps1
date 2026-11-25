$ErrorActionPreference = 'Stop'
$python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'

if (-not (Test-Path -LiteralPath $python)) {
    Write-Error 'Project virtual environment not found. Create .venv and install requirements first.'
    exit 1
}

Write-Host 'Checking public IPv4 and Atlas project access list...'
& $python (Join-Path $PSScriptRoot 'atlas_ip_allowlist.py')
if ($LASTEXITCODE -ne 0) {
    Write-Error 'Atlas IP allowlist setup failed. Flask was not started.'
    exit $LASTEXITCODE
}

Write-Host 'Starting Fraud Email Detection...'
& $python (Join-Path $PSScriptRoot 'app.py')
exit $LASTEXITCODE
