param([switch]$Elevated)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  $launchArguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Elevated'
  Start-Process -FilePath 'powershell.exe' -ArgumentList $launchArguments -Verb RunAs -WindowStyle Hidden
  exit
}
try {
  Set-Location -LiteralPath $PSScriptRoot
  $nodePath = (Get-Command node.exe -ErrorAction Stop).Source
  $serverPath = Join-Path $PSScriptRoot 'server.mjs'
  $statePath = Join-Path $PSScriptRoot 'data/server.json'
  $listener = Get-NetTCPConnection -LocalPort 4317 -State Listen -ErrorAction SilentlyContinue
  if ($listener) {
    if (-not (Test-Path -LiteralPath $statePath)) { throw '4317番ポートは別のアプリが使用しています。終了してから起動してください。' }
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    $processInfo = Get-CimInstance Win32_Process -Filter "ProcessId = $([int]$state.pid)"
    $expectedStart = [DateTimeOffset]::FromUnixTimeMilliseconds([long]$state.startedMs).UtcDateTime
    if (-not $processInfo -or $processInfo.ExecutablePath -ne $nodePath -or -not $processInfo.CommandLine.Contains($serverPath) -or [Math]::Abs(($processInfo.CreationDate.ToUniversalTime() - $expectedStart).TotalSeconds) -gt 3 -or $listener.OwningProcess -ne $state.pid) {
      throw '起動済みプロセスを安全に識別できません。既存のアプリを終了してから再実行してください。'
    }
  }
  & (Join-Path $PSScriptRoot 'enable-auditing.ps1')
  if ($listener) {
    Stop-Process -Id $state.pid -ErrorAction Stop
    Wait-Process -Id $state.pid -Timeout 5 -ErrorAction SilentlyContinue
  }
  $newServer = Start-Process -FilePath $nodePath -ArgumentList ('"' + $serverPath + '"') -WorkingDirectory $PSScriptRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $PSScriptRoot 'data/server-output.log') -RedirectStandardError (Join-Path $PSScriptRoot 'data/server-error.log') -PassThru
  $ready = $false
  for ($attempt = 0; $attempt -lt 15; $attempt++) {
    Start-Sleep -Milliseconds 500
    try { $check=Invoke-RestMethod -Uri 'http://127.0.0.1:4317/api/dashboard' -TimeoutSec 2; $ready=$true; break } catch {}
    if ($newServer.HasExited) { break }
  }
  if (-not $ready) { throw 'アプリを起動できませんでした。data/server-error.log を確認してください。' }
  Start-Process 'http://127.0.0.1:4317'
} catch {
  $_.Exception.Message | Out-File -LiteralPath (Join-Path $PSScriptRoot 'data/start-error.log') -Encoding UTF8
  Add-Type -AssemblyName System.Windows.Forms
  [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'SENTINEL 起動エラー') | Out-Null
  exit 1
}
