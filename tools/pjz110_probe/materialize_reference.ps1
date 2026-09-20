param(
    [string]$OutDir = (Join-Path $PSScriptRoot "out")
)

$ErrorActionPreference = "Stop"

$expected = "17305dd5136bafed35b39ec0b883c66f2f9d7ef78bffafb37fc88b9efb393931"
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
Write-Host "Behavior: prints three fixed lines, waits 5 seconds with BootServices.Stall(), returns EFI_SUCCESS"
