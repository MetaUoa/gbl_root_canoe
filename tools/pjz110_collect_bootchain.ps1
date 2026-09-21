param(
    [string]$OutDir = ("pjz110-bootchain-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    throw "adb was not found in PATH"
}

$model = ((& adb shell getprop ro.product.model) -join "").Trim()
$slot = ((& adb shell getprop ro.boot.slot_suffix) -join "").Trim()
$build = ((& adb shell getprop ro.build.display.id) -join "").Trim()

if ($model -ne "PJZ110") {
    throw "Refusing non-PJZ110 device: $model"
}
if ($slot -ne "_a" -and $slot -ne "_b") {
    throw "Unable to determine active slot: $slot"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Copy-BlockReadOnly([string]$Partition, [string]$Destination) {
    Write-Host "Reading $Partition -> $Destination"

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = "adb"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    [void]$psi.ArgumentList.Add("exec-out")
    [void]$psi.ArgumentList.Add("su")
    [void]$psi.ArgumentList.Add("-c")
    [void]$psi.ArgumentList.Add("cat /dev/block/by-name/$Partition")

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    if (-not $proc.Start()) {
        throw "Failed to start adb for $Partition"
    }

    $fs = [System.IO.File]::Open($Destination, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
    try {
        $proc.StandardOutput.BaseStream.CopyTo($fs)
    }
    finally {
        $fs.Dispose()
    }

    $stderr = $proc.StandardError.ReadToEnd()
    $proc.WaitForExit()
    if ($proc.ExitCode -ne 0) {
        Remove-Item -Force -ErrorAction SilentlyContinue $Destination
        throw "Read failed for $Partition : $stderr"
    }
    if ((Get-Item $Destination).Length -eq 0) {
        Remove-Item -Force -ErrorAction SilentlyContinue $Destination
        throw "Read returned an empty file for $Partition"
    }
}

$slotLetter = $slot.Substring(1)
$parts = @(
    "imagefv_$slotLetter",
    "uefi_$slotLetter",
    "toolsfv"
)

$manifest = [ordered]@{
    model = $model
    build = $build
    slot = $slot
    operation = "read-only partition capture"
    partitions = @()
}

foreach ($part in $parts) {
    $exists = ((& adb shell "su -c 'test -e /dev/block/by-name/$part && echo yes || echo no'") -join "").Trim()
    if ($exists -ne "yes") {
        Write-Warning "$part does not exist; skipping"
        continue
    }

    $dst = Join-Path $OutDir ($part + ".img")
    Copy-BlockReadOnly $part $dst
    $item = Get-Item $dst
    $hash = (Get-FileHash -Algorithm SHA256 $dst).Hash.ToLowerInvariant()
    $manifest.partitions += [ordered]@{
        name = $part
        file = $item.Name
        size = $item.Length
        sha256 = $hash
    }
    Write-Host ("  size={0} sha256={1}" -f $item.Length, $hash)
}

$manifest | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 (Join-Path $OutDir "manifest.json")

Write-Host ""
Write-Host "Read-only capture completed:"
Write-Host (Resolve-Path $OutDir)
Write-Host "No device partition was written."
