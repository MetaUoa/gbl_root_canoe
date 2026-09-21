param(
    [string]$OutDir = ("pjz110-efivars-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
)

$ErrorActionPreference = "Stop"
$GlobalGuid = "8be4df61-93ca-11d2-aa0d-00e098032b8c"

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    throw "adb was not found in PATH"
}

$devices = (& adb devices) -join [Environment]::NewLine
if ($devices -notmatch "\tdevice(\r)?$") {
    throw "No authorized adb device found"
}

$model = ((& adb shell getprop ro.product.model) -join "").Trim()
$build = ((& adb shell getprop ro.build.display.id) -join "").Trim()
$slot  = ((& adb shell getprop ro.boot.slot_suffix) -join "").Trim()

if ($model -ne "PJZ110") {
    throw "Refusing non-PJZ110 device: $model"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$rawDir = Join-Path $OutDir "efivars"
New-Item -ItemType Directory -Force -Path $rawDir | Out-Null

function Adb-Text([string]$Command) {
    $text = (& adb shell "su -c '$Command'" 2>&1) -join [Environment]::NewLine
    return $text.Trim()
}

function Save-Text([string]$Name, [string]$Command) {
    $value = Adb-Text $Command
    $value | Set-Content -Encoding utf8 (Join-Path $OutDir $Name)
    return $value
}

function Copy-RemoteBinary([string]$RemotePath, [string]$Destination) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = "adb"
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    [void]$psi.ArgumentList.Add("exec-out")
    [void]$psi.ArgumentList.Add("su")
    [void]$psi.ArgumentList.Add("-c")
    [void]$psi.ArgumentList.Add("cat '$RemotePath'")

    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    if (-not $proc.Start()) {
        throw "Failed to start adb while reading $RemotePath"
    }

    $fs = [System.IO.File]::Open(
        $Destination,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::Write
    )
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
        throw "Read failed for $RemotePath : $stderr"
    }
}

$mounts = Save-Text "mounts.txt" "cat /proc/mounts"
$efiTree = Save-Text "efi-tree.txt" "ls -la /sys/firmware/efi 2>/dev/null; ls -la /sys/firmware/efi/efivars 2>/dev/null; ls -la /sys/firmware/efi/vars 2>/dev/null"
$aux = Save-Text "uefisecapp-devices.txt" "find /sys/bus/auxiliary/devices /sys/bus/platform/devices -maxdepth 2 \( -iname '*uefisecapp*' -o -iname '*qseecom*' \) -print 2>/dev/null"
$modules = Save-Text "modules.txt" "cat /proc/modules 2>/dev/null"
$dmesg = Save-Text "uefisecapp-dmesg.txt" "dmesg 2>/dev/null | grep -Ei 'uefisecapp|qseecom|efivars|efivarfs' | tail -n 200"
$config = Save-Text "kernel-config.txt" "(zcat /proc/config.gz 2>/dev/null || cat /sys/kernel/config.gz 2>/dev/null || true) | grep -E 'CONFIG_(EFI|QCOM_QSEECOM|QCOM_QSEECOM_UEFISECAPP)='"

$efivarDir = ""
foreach ($candidate in @("/sys/firmware/efi/efivars", "/sys/firmware/efi/vars")) {
    $exists = Adb-Text "test -d '$candidate' && echo yes || echo no"
    if ($exists -eq "yes") {
        $efivarDir = $candidate
        break
    }
}

$efivarFsMounted = $false
if ($mounts -match "(?m)\s/sys/firmware/efi/efivars\s+efivarfs\s") {
    $efivarFsMounted = $true
}

$registered = ($dmesg -match "Registered efivars operations") -or
              ($aux -match "uefisecapp") -or
              ($modules -match "qcom_qseecom_uefisecapp")

$bootVarFiles = @()
if ($efivarDir -and $efivarFsMounted) {
    $names = Adb-Text "find '$efivarDir' -maxdepth 1 -type f \( -name 'BootNext-*' -o -name 'BootOrder-*' -o -name 'Boot[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]-*' \) -printf '%f\n' 2>/dev/null | sort"
    $names | Set-Content -Encoding utf8 (Join-Path $OutDir "boot-variable-names.txt")

    foreach ($name in ($names -split "\r?\n")) {
        if ([string]::IsNullOrWhiteSpace($name)) {
            continue
        }
        $remote = "$efivarDir/$name"
        $local = Join-Path $rawDir $name
        Copy-RemoteBinary $remote $local
        $item = Get-Item $local
        $hash = (Get-FileHash -Algorithm SHA256 $local).Hash.ToLowerInvariant()
        $bootVarFiles += [ordered]@{
            name = $name
            size = $item.Length
            sha256 = $hash
        }
    }
}

$uefivarstoreExists = (Adb-Text "test -e /dev/block/by-name/uefivarstore && echo yes || echo no") -eq "yes"

$next = if ($efivarFsMounted -and $bootVarFiles.Count -gt 0) {
    "Use the captured Boot#### variable as a device-path template; do not raw-edit uefivarstore."
}
elseif ($registered) {
    "Qualcomm UEFI variable backend appears present but efivarfs is not mounted/exposed. Validate mount capability before any write."
}
elseif ($uefivarstoreExists) {
    "No Linux efivar interface detected. Capture uefivarstore read-only for offline parsing before considering any mutation."
}
else {
    "No supported UEFI-variable path detected."
}

$summary = [ordered]@{
    schema = 1
    model = $model
    build = $build
    slot = $slot
    global_variable_guid = $GlobalGuid
    qcom_uefisecapp_detected = [bool]$registered
    efivarfs_mounted = [bool]$efivarFsMounted
    efivar_directory = $efivarDir
    uefivarstore_partition_exists = [bool]$uefivarstoreExists
    captured_boot_variables = $bootVarFiles
    read_only = $true
    recommended_next = $next
}

$summary | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 (Join-Path $OutDir "summary.json")
$summary | Format-List

Write-Host ""
Write-Host "Read-only EFI variable capability probe completed:"
Write-Host (Resolve-Path $OutDir)
Write-Host "No UEFI variable and no device partition was modified."
