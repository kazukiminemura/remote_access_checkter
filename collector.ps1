$ErrorActionPreference = 'Stop'
$result = @{ events=@(); firewall=@(); localIPs=@(); status=@(); hostname=$env:COMPUTERNAME }
$since = (Get-Date).AddHours(-24)
try {
  $result.localIPs = @(Get-NetIPAddress | Where-Object { $_.AddressState -eq 'Preferred' } | ForEach-Object IPAddress)
} catch { $result.status += @{name='network';ok=$false;message=$_.Exception.Message} }
try {
  $securityLog = Get-WinEvent -ListLog Security -ErrorAction Stop
  if (-not $securityLog.IsEnabled) { throw 'Securityログが無効です' }
  $logs = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4608,4624,4625,4634,4688;StartTime=$since} -MaxEvents 20000 -ErrorAction Stop)
  $result.events = @($logs | ForEach-Object {
    $xml=[xml]$_.ToXml(); $fields=@{}
    foreach ($item in $xml.Event.EventData.Data) { $fields[$item.Name]=[string]$item.'#text' }
    @{eventId=$_.Id;recordId=$_.RecordId;time=$_.TimeCreated.ToUniversalTime().ToString('o');data=$fields}
  })
  $result.status += @{name='security';ok=$true;message='過去24時間のSecurityログ取得済み';limited=($logs.Count -ge 20000)}
} catch {
  if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $result.status += @{name='security';ok=$true;message='対象イベントなし。監査設定を確認してください'} }
  else { $result.status += @{name='security';ok=$false;message='Securityログを読めません。管理者として起動してください'} }
}
try {
  $profiles = @(Get-NetFirewallProfile)
  $paths = @($profiles | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.LogFileName) } | Select-Object -Unique)
  foreach ($path in $paths) {
    if (Test-Path -LiteralPath $path) {
      # Read the header separately because a capped tail may no longer contain #Fields.
      $header = @(Get-Content -LiteralPath $path -TotalCount 15 | Where-Object { $_ -like '#Fields:*' })
      $tail = @(Get-Content -LiteralPath $path -Tail 20000)
      $result.firewall += @{path=$path;text=(($header + $tail) -join "`n");limited=($tail.Count -ge 20000)}
    }
  }
  $active = @($profiles | Where-Object { $_.LogAllowed -and $_.LogBlocked }).Count
  $result.status += @{name='firewall';ok=($active -eq 3 -and $result.firewall.Count -gt 0);message="記録有効: $active / 3 プロファイル。ログファイル: $($result.firewall.Count)"}
} catch { $result.status += @{name='firewall';ok=$false;message='Firewallログを読めません。管理者権限と記録設定を確認してください'} }
$result | ConvertTo-Json -Depth 6 -Compress
