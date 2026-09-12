[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $repoRoot

if (-not (Get-Command cargo-llvm-cov -ErrorAction SilentlyContinue)) {
    throw 'cargo-llvm-cov is missing. Run scripts/bootstrap.ps1 -InstallTools.'
}

$coverageDir = Join-Path $repoRoot 'target/coverage'
New-Item -ItemType Directory -Force -Path $coverageDir | Out-Null

cargo llvm-cov --workspace --all-features --fail-under-lines 100 --fail-under-regions 100
if ($LASTEXITCODE -ne 0) { throw 'Coverage gate failed.' }

cargo llvm-cov --workspace --all-features --lcov --output-path (Join-Path $coverageDir 'lcov.info')
if ($LASTEXITCODE -ne 0) { throw 'LCOV generation failed.' }

cargo llvm-cov --workspace --all-features --html --output-dir $coverageDir
if ($LASTEXITCODE -ne 0) { throw 'HTML coverage generation failed.' }

Write-Host "Coverage report: $(Join-Path $coverageDir 'html/index.html')"
