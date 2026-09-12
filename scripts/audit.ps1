[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$reportDir = Join-Path $repoRoot 'reports'
Set-Location -LiteralPath $repoRoot
New-Item -ItemType Directory -Force -Path $reportDir | Out-Null

foreach ($tool in @('cargo-deny', 'cargo-audit')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool is missing. Run scripts/bootstrap.ps1 -InstallTools."
    }
}

$ErrorActionPreference = 'Continue'
cargo deny check 2>&1 | Tee-Object -FilePath (Join-Path $reportDir 'cargo-deny.txt')
$denyExitCode = $LASTEXITCODE
cargo audit 2>&1 | Tee-Object -FilePath (Join-Path $reportDir 'cargo-audit.txt')
$auditExitCode = $LASTEXITCODE
$ErrorActionPreference = 'Stop'

if ($denyExitCode -ne 0) { throw 'cargo deny failed.' }
if ($auditExitCode -ne 0) { throw 'cargo audit failed.' }
