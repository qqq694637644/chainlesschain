#requires -version 5.1
<#
.SYNOPSIS
  Install/check Frida tools, download the matching frida-server for Android,
  push it to the rooted device, and start it.

.DESCRIPTION
  This is a standalone helper for the lightweight WeChat decrypt flow. It does
  not use the ChainlessChain CLI or npm workspace dependencies.

  It intentionally downloads frida-server with the same version as the locally
  installed Python `frida` package. Host Frida and device frida-server versions
  must match.

.EXAMPLE
  .\tools\wechat-frida-start-server.ps1

.EXAMPLE
  .\tools\wechat-frida-start-server.ps1 -Port 13337
#>

param(
  [string]$Adb = "adb",
  [string]$Device = "",
  [string]$Out = "C:\wechat-stage",
  [int]$Port = 27042,
  [switch]$ForceDownload,
  [switch]$SkipPipInstall
)

$ErrorActionPreference = "Stop"

function Invoke-Adb {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
  $full = @()
  if ($Device) { $full += @("-s", $Device) }
  $full += $Args
  & $Adb @full
}

function Assert-LastExitCode {
  param([string]$What)
  if ($LASTEXITCODE -ne 0) { throw "$What failed with exit code $LASTEXITCODE" }
}

function Get-PythonCommand {
  $candidates = @("py", "python")
  foreach ($c in $candidates) {
    try {
      & $c --version *> $null
      if ($LASTEXITCODE -eq 0) { return $c }
    } catch {}
  }
  throw "Python not found. Install Python 3 first, or ensure py/python is in PATH."
}

function Get-FridaVersion {
  param([string]$Python)
  $ver = & $Python -c "import frida; print(frida.__version__)" 2>$null
  if ($LASTEXITCODE -ne 0 -or -not $ver) { return $null }
  return ($ver | Select-Object -First 1).Trim()
}

function Get-PythonUserScripts {
  param([string]$Python)
  $dir = & $Python -c "import site, os; print(os.path.join(site.USER_BASE, 'Scripts'))"
  Assert-LastExitCode "detect Python user scripts dir"
  return ($dir | Select-Object -First 1).Trim()
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null

Write-Host "[1/7] Checking adb device..."
Invoke-Adb devices | ForEach-Object { Write-Host $_ }
Assert-LastExitCode "adb devices"

Write-Host "[2/7] Checking root..."
$rootId = Invoke-Adb shell su -c id
Assert-LastExitCode "adb shell su -c id"
Write-Host $rootId
if (-not ($rootId -match "uid=0")) { throw "Root is required. adb shell su -c id did not return uid=0." }

Write-Host "[3/7] Preparing host Frida tools..."
$python = Get-PythonCommand
if (-not $SkipPipInstall) {
  & $python -m pip install --user --upgrade frida-tools
  Assert-LastExitCode "pip install frida-tools"
}
$scriptsDir = Get-PythonUserScripts -Python $python
$env:Path = "$scriptsDir;$env:Path"
$fridaVersion = Get-FridaVersion -Python $python
if (-not $fridaVersion) { throw "Failed to import Python frida package after installation." }
Write-Host "Host Frida version: $fridaVersion"

Write-Host "[4/7] Detecting Android ABI..."
$abi = (Invoke-Adb shell getprop ro.product.cpu.abi | Select-Object -First 1).Trim()
Assert-LastExitCode "adb getprop abi"
Write-Host "Device ABI: $abi"
$fridaArch = switch -Regex ($abi) {
  '^arm64' { 'android-arm64'; break }
  '^armeabi|^arm' { 'android-arm'; break }
  '^x86_64' { 'android-x86_64'; break }
  '^x86' { 'android-x86'; break }
  default { throw "Unsupported Android ABI: $abi" }
}

$serverName = "frida-server-$fridaVersion-$fridaArch"
$xzPath = Join-Path $Out "$serverName.xz"
$serverPath = Join-Path $Out "frida-server"
$url = "https://github.com/frida/frida/releases/download/$fridaVersion/$serverName.xz"

Write-Host "[5/7] Downloading matching frida-server if needed..."
if ($ForceDownload -or -not (Test-Path $serverPath)) {
  if ($ForceDownload -or -not (Test-Path $xzPath)) {
    Write-Host $url
    Invoke-WebRequest -Uri $url -OutFile $xzPath
  }
  & $python -c "import lzma, sys, shutil; shutil.copyfileobj(lzma.open(sys.argv[1], 'rb'), open(sys.argv[2], 'wb'))" $xzPath $serverPath
  Assert-LastExitCode "decompress frida-server"
}

Write-Host "[6/7] Pushing and starting frida-server..."
Invoke-Adb push $serverPath /data/local/tmp/frida-server | ForEach-Object { Write-Host $_ }
Assert-LastExitCode "adb push frida-server"
Invoke-Adb shell su -c "chmod 755 /data/local/tmp/frida-server; pkill -9 frida-server 2>/dev/null; /data/local/tmp/frida-server -D -l 0.0.0.0:$Port"
Assert-LastExitCode "start frida-server"
Start-Sleep -Seconds 1

Write-Host "[7/7] Verifying frida-server..."
Invoke-Adb shell su -c "pgrep -f frida-server"
Assert-LastExitCode "pgrep frida-server"

# `frida-ps -U` verifies host<->device protocol compatibility.
& frida-ps -U | Select-Object -First 12 | ForEach-Object { Write-Host $_ }
Assert-LastExitCode "frida-ps -U"

Write-Host ""
Write-Host "OK. frida-server is running on device, port $Port."
Write-Host "Next: powershell -ExecutionPolicy Bypass -File .\tools\wechat-frida-capture-key.ps1"
