param(
    [string]$OutDir = (Join-Path $PSScriptRoot "out")
)

$ErrorActionPreference = "Stop"

$expected = "2c7ef30661f8f09bfca56e481c84b1b18a8f4df9a92e2916fa75cb0d51047738"
$source = Join-Path $PSScriptRoot "BOOTAA64.EFI.b64"
if (-not (Test-Path $source)) {
    throw "Reference base64 payload not found: $source"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$out = Join-Path $OutDir "BOOTAA64.EFI"

$raw = (Get-Content -Raw $source).Trim()
$bytes = [Convert]::FromBase64String($raw)
[IO.File]::WriteAllBytes($out, $bytes)

$hash = (Get-FileHash -Algorithm SHA256 $out).Hash.ToLowerInvariant()
if ($bytes.Length -ne 2048) {
    Remove-Item -Force $out
    throw "Reference probe size mismatch: $($bytes.Length) != 2048"
}
if ($hash -ne $expected) {
    Remove-Item -Force $out
    throw "Reference probe SHA256 mismatch: $hash != $expected"
}

Write-Host "Materialized: $out"
Write-Host "Size: 2048"
Write-Host "SHA256: $hash"
