# Run explicitly in an elevated PowerShell. This does not change firewall rules or open ports.
# Command-line auditing can record passwords/tokens passed as command arguments.
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw '管理者としてPowerShellを開いて実行してください。' }
$backup = Join-Path $PSScriptRoot 'data/audit-policy-before.csv'
if (-not (Test-Path -LiteralPath $backup)) { & auditpol /backup /file:$backup; if ($LASTEXITCODE -ne 0) { throw '監査設定のバックアップに失敗しました' } }
Set-NetFirewallProfile -Profile Domain,Private,Public -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 32767
# Language-independent subcategory GUIDs: Logon, Logoff, Process Creation.
foreach ($guid in @('{0CCE9215-69AE-11D9-BED3-505054503030}','{0CCE9216-69AE-11D9-BED3-505054503030}','{0CCE922B-69AE-11D9-BED3-505054503030}')) {
  & auditpol /set /subcategory:$guid /success:enable /failure:enable
  if ($LASTEXITCODE -ne 0) { throw "監査設定に失敗しました: $guid" }
}
# Opt-in: ./enable-auditing.ps1 -CommandLine (see param handling below).
if ($args -contains '-CommandLine') {
  $key='HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
  New-Item -Path $key -Force | Out-Null
  New-ItemProperty -Path $key -Name ProcessCreationIncludeCmdLine_Enabled -PropertyType DWord -Value 1 -Force | Out-Null
}
Write-Host '記録を有効化しました。アプリを管理者として起動してください。過去の未記録データは復元できません。'
