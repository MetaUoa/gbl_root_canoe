param(
    [string]$OutDir = (Join-Path $PSScriptRoot "out")
)

$ErrorActionPreference = "Stop"

$clang = Get-Command clang.exe -ErrorAction SilentlyContinue
if (-not $clang) { $clang = Get-Command clang -ErrorAction SilentlyContinue }
if (-not $clang) { throw "clang was not found in PATH (LLVM is required)" }

$lld = Get-Command lld-link.exe -ErrorAction SilentlyContinue
if (-not $lld) { $lld = Get-Command lld-link -ErrorAction SilentlyContinue }
if (-not $lld) { throw "lld-link was not found in PATH (LLVM is required)" }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$src = Join-Path $PSScriptRoot "pjz110_probe.c"
$obj = Join-Path $OutDir "pjz110_probe.obj"
$efi = Join-Path $OutDir "BOOTAA64.EFI"

$clangArgs = @(
  "--target=aarch64-pc-windows-msvc",
  "-ffreestanding", "-fshort-wchar", "-fno-stack-protector",
  "-fno-builtin", "-O1", "-c", $src, "-o", $obj
)
& $clang.Source @clangArgs
if ($LASTEXITCODE -ne 0) { throw "clang failed" }

$lldArgs = @(
  "/subsystem:efi_application", "/entry:efi_main", "/nodefaultlib",
  "/machine:arm64", "/base:0x100000", "/timestamp:0",
  "/out:$efi", $obj
)
& $lld.Source @lldArgs
if ($LASTEXITCODE -ne 0) { throw "lld-link failed" }

$hash = (Get-FileHash -Algorithm SHA256 $efi).Hash.ToLowerInvariant()
$size = (Get-Item $efi).Length
Write-Host "Built:  $efi"
Write-Host "Size:   $size"
Write-Host "SHA256: $hash"
