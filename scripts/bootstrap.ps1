[CmdletBinding()]
param([switch]$InstallTools)

$ErrorActionPreference = 'Stop'
$missing = [System.Collections.Generic.List[string]]::new()

foreach ($command in @('git', 'rustup', 'cargo')) {
    if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { $missing.Add($command) }
}

if ($missing.Count -gt 0) {
    Write-Error "Install these prerequisites first: $($missing -join ', '). See docs/development.md."
    exit 1
}

rustup show
rustup component add clippy llvm-tools-preview rustfmt
rustup target add x86_64-pc-windows-msvc

$cargoTools = @{
    'just' = 'just'
    'cargo-llvm-cov' = 'cargo-llvm-cov'
    'cargo-deny' = 'cargo-deny'
    'cargo-audit' = 'cargo-audit'
}

$missingTools = @($cargoTools.Keys | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
if ($InstallTools) {
    foreach ($command in $missingTools) {
        cargo install --locked $cargoTools[$command]
        if ($LASTEXITCODE -ne 0) { throw "Could not install $command." }
    }
    $missingTools = @($cargoTools.Keys | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
}

if ($missingTools.Count -gt 0) {
    Write-Warning "Missing developer tools: $($missingTools -join ', '). Re-run with -InstallTools."
    exit 2
}

Write-Host 'Vaero development prerequisites are ready.'
