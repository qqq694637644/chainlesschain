#requires -version 5.1
<#
.SYNOPSIS
  Capture Android WeChat SQLCipher raw key with Frida and write raw-keys files.

.DESCRIPTION
  This script starts WeChat via `frida -U -f com.tencent.mm`, loads
  tools/wechat-key-hook-standalone.js, monitors frida output, extracts the first
  JSON line with kind=key, and writes:

    C:\wechat-stage\raw-key.txt
    C:\wechat-stage\raw-keys.json
    C:\wechat-stage\frida-wechat-key.log

  While it is running, unlock the phone and enter any WeChat chat to trigger
  libWCDB/sqlite3_key. The script will stop Frida automatically after a key is
  captured or after TimeoutSeconds.

.EXAMPLE
  .\tools\wechat-frida-capture-key.ps1
#>

param(
  [string]$Out = "C:\wechat-stage",
  [string]$Agent = ".\tools\wechat-key-hook-standalone.js",
  [string]$Package = "com.tencent.mm",
  [int]$TimeoutSeconds = 180,
  [switch]$AttachOnly
)

$ErrorActionPreference = "Stop"

function Get-FridaCommand {
  $cmd = Get-Command frida -ErrorAction SilentlyContinue
  if ($cmd) { return $cmd.Source }

  $python = $null
  foreach ($c in @("py", "python")) {
    try {
      & $c --version *> $null
      if ($LASTEXITCODE -eq 0) { $python = $c; break }
    } catch {}
  }
  if ($python) {
    $scriptsDir = (& $python -c "import site, os; print(os.path.join(site.USER_BASE, 'Scripts'))" | Select-Object -First 1).Trim()
    if ($scriptsDir) {
      $env:Path = "$scriptsDir;$env:Path"
      $cmd = Get-Command frida -ErrorAction SilentlyContinue
      if ($cmd) { return $cmd.Source }
    }
  }
  throw "frida command not found. Run tools\wechat-frida-start-server.ps1 first, or install frida-tools."
}

function Extract-KeyJsonFromLog {
  param([string]$LogPath)
  if (-not (Test-Path $LogPath)) { return $null }

  $lines = Get-Content $LogPath -ErrorAction SilentlyContinue
  foreach ($line in $lines) {
    $matches = [regex]::Matches($line, '\{.*"kind"\s*:\s*"key".*\}')
    foreach ($m in $matches) {
      try {
        $obj = $m.Value | ConvertFrom-Json
        if ($obj.kind -eq "key" -and $obj.hex) { return $obj }
      } catch {}
    }
  }
  return $null
}

New-Item -ItemType Directory -Force -Path $Out | Out-Null
$agentPath = [System.IO.Path]::GetFullPath($Agent)
if (-not (Test-Path $agentPath)) { throw "Agent not found: $agentPath" }

$logPath = Join-Path $Out "frida-wechat-key.log"
$rawKeyPath = Join-Path $Out "raw-key.txt"
$rawKeysJsonPath = Join-Path $Out "raw-keys.json"
Remove-Item -Force $logPath, $rawKeyPath, $rawKeysJsonPath -ErrorAction SilentlyContinue

$frida = Get-FridaCommand

Write-Host "Starting Frida capture."
Write-Host "Phone action needed: unlock phone, let WeChat open, then enter any chat."
Write-Host "Log: $logPath"
Write-Host ""

$args = @("-U")
if ($AttachOnly) {
  $args += @("-n", $Package)
} else {
  $args += @("-f", $Package, "--no-pause")
}
$args += @("-l", $agentPath, "-o", $logPath)

$stdoutPath = Join-Path $Out "frida-run.stdout.txt"
$stderrPath = Join-Path $Out "frida-run.stderr.txt"
Remove-Item -Force $stdoutPath, $stderrPath -ErrorAction SilentlyContinue

$proc = Start-Process -FilePath $frida -ArgumentList $args -NoNewWindow -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$keyObj = $null

try {
  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 1
    $keyObj = Extract-KeyJsonFromLog -LogPath $logPath
    if ($keyObj) { break }
    if ($proc.HasExited) {
      $keyObj = Extract-KeyJsonFromLog -LogPath $logPath
      if ($keyObj) { break }
      throw "frida exited before key capture. See $stdoutPath and $stderrPath"
    }
  }
} finally {
  if (-not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  }
}

if (-not $keyObj) {
  Write-Host ""
  Write-Warning "No key captured within $TimeoutSeconds seconds."
  Write-Host "Diagnostics:"
  if (Test-Path $logPath) { Get-Content $logPath -Tail 80 }
  if (Test-Path $stderrPath) { Get-Content $stderrPath -Tail 40 }
  throw "No key captured. Try again after force-stopping WeChat, or use -AttachOnly when WeChat is already open."
}

$key = [string]$keyObj.hex
$key = $key.Trim().ToLowerInvariant()
if ($key -notmatch '^[0-9a-f]{64}$') {
  throw "Captured key is not 64 hex chars: $key"
}

Set-Content -Path $rawKeyPath -Value $key -NoNewline -Encoding ASCII
@($key) | ConvertTo-Json | Set-Content -Path $rawKeysJsonPath -Encoding UTF8

Write-Host ""
Write-Host "OK. Captured raw key:"
Write-Host $key
Write-Host ""
Write-Host "Saved:"
Write-Host "  $rawKeyPath"
Write-Host "  $rawKeysJsonPath"
Write-Host ""
Write-Host "Next command:"
Write-Host "`$rawKey = Get-Content `"$rawKeyPath`" -Raw"
Write-Host "node .\tools\wechat-decrypt-standalone.js --db C:\wechat-stage\enmm.enc.db --out C:\wechat-stage\decoded.db --raw-key `$rawKey.Trim() --force"
