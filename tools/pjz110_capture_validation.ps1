param(
    [string]$OutDir = ("pjz110-validation-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    throw "adb was not found in PATH"
}

$devices = (& adb devices) -join [Environment]::NewLine
if ($devices -notmatch "\tdevice(\r)?$") {
    throw "No authorized adb device found"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$model = ((& adb shell getprop ro.product.model) -join "").Trim()
$build = ((& adb shell getprop ro.build.display.id) -join "").Trim()
$slot  = ((& adb shell getprop ro.boot.slot_suffix) -join "").Trim()

if ($model -ne "PJZ110") {
    throw "Refusing non-PJZ110 device: $model"
}

& adb shell getprop | Out-File -Encoding utf8 "$OutDir/getprop.txt"
& adb shell cat /proc/bootconfig | Out-File -Encoding utf8 "$OutDir/bootconfig.txt"
& adb shell cat /proc/cmdline | Out-File -Encoding utf8 "$OutDir/cmdline.txt"
& adb shell "su -c 'ls -l /dev/block/by-name'" | Out-File -Encoding utf8 "$OutDir/partitions.txt"

$bootconfig = Get-Content "$OutDir/bootconfig.txt" -Raw
$getprop = Get-Content "$OutDir/getprop.txt" -Raw

function Match-BootConfig([string]$Name) {
    $pattern = '(?m)^' + [regex]::Escape($Name) + '\s*=\s*"([^"]+)"'
    $m = [regex]::Match($bootconfig, $pattern)
    if ($m.Success) { return $m.Groups[1].Value }
    return ""
}

function Match-Prop([string]$Name) {
    $pattern = '(?m)^\[' + [regex]::Escape($Name) + '\]: \[([^\]]*)\]'
    $m = [regex]::Match($getprop, $pattern)
    if ($m.Success) { return $m.Groups[1].Value }
    return ""
}

$bcDevice = Match-BootConfig "androidboot.vbmeta.device_state"
$bcVerified = Match-BootConfig "androidboot.verifiedbootstate"
$propDevice = Match-Prop "ro.boot.vbmeta.device_state"
$propVerified = Match-Prop "ro.boot.verifiedbootstate"
$propFlashLocked = Match-Prop "ro.boot.flash.locked"

$ablPass = ($bcDevice -eq "locked" -and $bcVerified -eq "green")
$userspaceOnly = (-not $ablPass -and $propDevice -eq "locked" -and $propVerified -eq "green")

$summary = [ordered]@{
    model = $model
    build = $build
    slot = $slot
    bootconfig_device_state = $bcDevice
    bootconfig_verifiedbootstate = $bcVerified
    getprop_device_state = $propDevice
    getprop_verifiedbootstate = $propVerified
    getprop_flash_locked = $propFlashLocked
    abl_fake_lock_pass = $ablPass
    userspace_spoof_only = $userspaceOnly
    criterion = "PASS requires /proc/bootconfig locked + green while real bootloader remains unlocked"
}

$summary | ConvertTo-Json | Set-Content -Encoding utf8 "$OutDir/summary.json"
$summary | Format-List

if ($userspaceOnly) {
    Write-Host ""
    Write-Host "RESULT: FAIL (userspace/property spoof only; ABL still reports real unlocked/orange state)"
    exit 2
}
if ($ablPass) {
    Write-Host ""
    Write-Host "RESULT: ABL OUTPUT PASS. Confirm real bootloader remains unlocked separately in fastboot."
    exit 0
}

Write-Host ""
Write-Host "RESULT: FAIL (ABL output is not locked/green)"
exit 1
