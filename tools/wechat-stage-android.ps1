#requires -version 5.1
<#
.SYNOPSIS
  Stage the minimum Android WeChat files needed by tools/wechat-decrypt-standalone.js.

.DESCRIPTION
  This is a lightweight extraction of the ChainlessChain/Magisk staging flow.
  It does not load the ChainlessChain CLI, npm workspaces, Electron, or native
  sqlite packages. It only calls adb + su on a rooted Android device.

  Output files:
    enmm.enc.db  - copied EnMicroMsg.db
    uins.txt     - numeric UIN candidates from WeChat shared_prefs
    imeis.txt    - Android ID / IMEI candidates when readable
    info.txt     - diagnostic device and WeChat information

  Use only for databases you are authorized to access.

.EXAMPLE
  .\tools\wechat-stage-android.ps1 -Out .\wechat-stage

.EXAMPLE
  .\tools\wechat-stage-android.ps1 -Adb C:\Users\Administrator\Desktop\platform-tools\adb.exe -Out C:\wechat-stage
#>

param(
  [string]$Out = (Join-Path (Get-Location) "wechat-stage"),
  [string]$Adb = "adb",
  [string]$Device = "",
  [string]$DbPath = "",
  [switch]$KeepDeviceTemp
)

$ErrorActionPreference = "Stop"

function Invoke-Adb {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
  $full = @()
  if ($Device) { $full += @("-s", $Device) }
  $full += $Args
  & $Adb @full
}

function Invoke-AdbOptional {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
  $full = @()
  if ($Device) { $full += @("-s", $Device) }
  $full += $Args

  # Missing optional diagnostic files should not terminate the whole staging
  # script. Windows PowerShell can surface native stderr as NativeCommandError
  # when ErrorActionPreference is Stop, so temporarily relax it here.
  $oldEap = $ErrorActionPreference
  try {
    $ErrorActionPreference = "Continue"
    & $Adb @full 2>$null | Out-Null
    return $LASTEXITCODE
  } finally {
    $ErrorActionPreference = $oldEap
  }
}

function Assert-LastExitCode {
  param([string]$What)
  if ($LASTEXITCODE -ne 0) {
    throw "$What failed with exit code $LASTEXITCODE"
  }
}

function Quote-ShSingle {
  param([string]$Value)
  return "'" + ($Value -replace "'", "'\\''") + "'"
}

Write-Host "[1/6] Checking adb..."
$devices = Invoke-Adb devices
Assert-LastExitCode "adb devices"
$devices | ForEach-Object { Write-Host $_ }
if (-not ($devices -match "\tdevice$")) {
  throw "No authorized adb device found. Run: adb devices, then approve USB debugging on the phone."
}

Write-Host "[2/6] Checking root..."
$rootId = Invoke-Adb shell su -c id
Assert-LastExitCode "adb shell su -c id"
Write-Host $rootId
if (-not ($rootId -match "uid=0")) {
  throw "su did not return uid=0. The phone must be rooted and Magisk/SU must allow adb shell."
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$remoteDir = "/data/local/tmp/cc-wechat-stage-$stamp"
$remoteScript = "/data/local/tmp/cc-wechat-stage-$stamp.sh"
$localOut = [System.IO.Path]::GetFullPath($Out)
New-Item -ItemType Directory -Force -Path $localOut | Out-Null

$dbPathLiteral = $DbPath
$script = @'
#!/system/bin/sh
WX="com.tencent.mm"
OUT="__REMOTE_DIR__"
DBPATH="__DB_PATH__"

rm -rf "$OUT" 2>/dev/null
mkdir -p "$OUT" || exit 10

if [ -z "$DBPATH" ]; then
  DBPATH=$(find /data/data/$WX/MicroMsg -name EnMicroMsg.db 2>/dev/null | head -1)
fi

if [ -z "$DBPATH" ]; then
  echo "ERROR: EnMicroMsg.db not found. Is WeChat installed and logged in?" > "$OUT/error.txt"
  chmod 644 "$OUT/error.txt" 2>/dev/null
  exit 20
fi

if ! cp "$DBPATH" "$OUT/enmm.enc.db" 2>"$OUT/cp-db.err"; then
  echo "ERROR: copy EnMicroMsg.db failed: $DBPATH" > "$OUT/error.txt"
  chmod 644 "$OUT"/* 2>/dev/null
  exit 21
fi

# ChainlessChain staging logic: UIN candidates from shared_prefs.
grep -rohE '\-?[0-9]{4,12}' /data/data/$WX/shared_prefs/ 2>/dev/null \
  | sort -u | head -200 > "$OUT/uins.txt" 2>/dev/null

# ChainlessChain staging logic: Android ID plus best-effort IMEI from service call.
{
  settings get secure android_id 2>/dev/null
  service call iphonesubinfo 1 2>/dev/null | grep -oE "'.{8,}'" | tr -d "'. " | tr -d '\n'; echo
} | sort -u > "$OUT/imeis.txt" 2>/dev/null

{
  echo "dbPath=$DBPATH"
  echo "abi=$(getprop ro.product.cpu.abi 2>/dev/null)"
  echo "model=$(getprop ro.product.model 2>/dev/null)"
  echo "android=$(getprop ro.build.version.release 2>/dev/null)"
  dumpsys package $WX 2>/dev/null | grep versionName | head -1
  echo ""
  echo "staged files:"
  ls -l "$OUT" 2>/dev/null
} > "$OUT/info.txt" 2>/dev/null

chmod 644 "$OUT"/* 2>/dev/null
exit 0
'@

$script = $script.Replace("__REMOTE_DIR__", $remoteDir).Replace("__DB_PATH__", ($dbPathLiteral -replace '"', '\"'))
# Android /system/bin/sh expects LF line endings. If this temporary script is
# written with Windows CRLF, sh sees stray \r characters and fails with errors
# such as "inaccessible or not found" or "syntax error: unexpected '|'".
$script = $script -replace "`r`n", "`n"
$script = $script -replace "`r", "`n"
$tmpScript = Join-Path $env:TEMP "cc-wechat-stage-$stamp.sh"
[System.IO.File]::WriteAllText($tmpScript, $script, [System.Text.UTF8Encoding]::new($false))

Write-Host "[3/6] Pushing staging script..."
Invoke-Adb push $tmpScript $remoteScript | Write-Host
Assert-LastExitCode "adb push staging script"
Invoke-Adb shell chmod 755 $remoteScript | Out-Null
Assert-LastExitCode "chmod staging script"

Write-Host "[4/6] Staging WeChat files on device..."
Invoke-Adb shell su -c "sh $remoteScript" | ForEach-Object { Write-Host $_ }
if ($LASTEXITCODE -ne 0) {
  Write-Warning "device-side staging failed; trying to pull diagnostics"
}

Write-Host "[5/6] Pulling staged files to $localOut ..."
foreach ($name in @("enmm.enc.db", "uins.txt", "imeis.txt", "info.txt", "error.txt", "cp-db.err")) {
  $target = Join-Path $localOut $name
  $null = Invoke-AdbOptional pull "$remoteDir/$name" $target
}

if (Test-Path (Join-Path $localOut "error.txt")) {
  Get-Content (Join-Path $localOut "error.txt") | ForEach-Object { Write-Error $_ }
  throw "WeChat staging failed. See $localOut"
}

foreach ($required in @("enmm.enc.db", "uins.txt", "imeis.txt")) {
  $p = Join-Path $localOut $required
  if (-not (Test-Path $p)) { throw "Missing staged file: $p" }
}

if (-not $KeepDeviceTemp) {
  Write-Host "[6/6] Cleaning device temp files..."
  Invoke-Adb shell su -c "rm -rf $remoteDir $remoteScript" | Out-Null
} else {
  Write-Host "[6/6] Keeping device temp files: $remoteDir"
}

Write-Host ""
Write-Host "OK. Staged files:"
Get-ChildItem $localOut | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
Write-Host ""
Write-Host "Next command:"
Write-Host "node tools\wechat-decrypt-standalone.js --db `"$localOut\enmm.enc.db`" --out `"$localOut\decoded.db`" --uins `"$localOut\uins.txt`" --imeis `"$localOut\imeis.txt`" --force"
