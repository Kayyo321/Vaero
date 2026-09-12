[CmdletBinding()]
param([string]$OutputDirectory = 'artifacts')

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $repoRoot

$metadata = cargo metadata --locked --no-deps --format-version 1 | ConvertFrom-Json
$version = ($metadata.packages | Where-Object name -eq 'vaero-cli').version
$output = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $OutputDirectory))
New-Item -ItemType Directory -Force -Path $output | Out-Null

cargo build --workspace --release --locked --target x86_64-pc-windows-msvc
if ($LASTEXITCODE -ne 0) { throw 'Release build failed.' }

$binary = Join-Path $repoRoot 'target/x86_64-pc-windows-msvc/release/vaero.exe'
$publishedBinary = Join-Path $output "vaero-$version-windows-x86_64.exe"
Copy-Item -LiteralPath $binary -Destination $publishedBinary -Force

$installer = Join-Path $output "install-vaero-$version.ps1"
$installerBody = @'
[CmdletBinding()]
param([string]$InstallDirectory = (Join-Path $env:LOCALAPPDATA 'Programs\Vaero'))
$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot '__BINARY__'
New-Item -ItemType Directory -Force -Path $InstallDirectory | Out-Null
Copy-Item -LiteralPath $source -Destination (Join-Path $InstallDirectory 'vaero.exe') -Force
Write-Host "Installed Vaero to $InstallDirectory"
'@.Replace('__BINARY__', (Split-Path -Leaf $publishedBinary))
Set-Content -LiteralPath $installer -Value $installerBody -Encoding UTF8

if ($env:VAERO_SIGN_CERTIFICATE) {
    $signTool = Get-Command signtool.exe -ErrorAction Stop
    & $signTool.Source sign /fd SHA256 /f $env:VAERO_SIGN_CERTIFICATE /p $env:VAERO_SIGN_PASSWORD $publishedBinary
    if ($LASTEXITCODE -ne 0) { throw "Signing failed for $publishedBinary." }
}

$zip = Join-Path $output "vaero-$version-windows-x86_64.zip"
Compress-Archive -LiteralPath $publishedBinary, $installer -DestinationPath $zip -Force

$publishFiles = @($publishedBinary, $installer, $zip)
$checksumFile = Join-Path $output 'SHA256SUMS.txt'
$checksums = foreach ($file in $publishFiles) {
    $stream = [IO.File]::OpenRead($file)
    try {
        $sha256 = [Security.Cryptography.SHA256]::Create()
        try { $hash = ([BitConverter]::ToString($sha256.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
        finally { $sha256.Dispose() }
    }
    finally { $stream.Dispose() }
    "$hash  $(Split-Path -Leaf $file)"
}
Set-Content -LiteralPath $checksumFile -Value $checksums -Encoding ascii

Write-Host "Release artifacts: $output"
