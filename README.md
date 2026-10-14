# SENTINEL — Network Observatory

このWindows PCへの外部アクセス、世界地図、リモート認証成功・失敗、認証後のプロセス作成を表示するローカルアプリ。Node.js 22以上。追加npm依存関係なし。

## 起動

1. このフォルダーで `npm start`（または `start.cmd` を実行）。
2. http://127.0.0.1:4317 を開く。
3. 「デモを見る」で架空のサンプルを表示。「実ログに戻る」で収集データを表示。

## 実ログの収集

`start-monitor.cmd` をダブルクリックし、WindowsのUACで「はい」を選ぶと、監査記録を有効化してアプリを管理者として起動する。SENTINEL自身の起動情報・PID・コマンド行・起動時刻が一致する場合だけ、起動済みのプレビューを終了して再起動する。別アプリが4317番ポートを使っている場合は停止せずエラーを表示。起動失敗の詳細は `data/start-error.log`。UAC昇格と監査設定変更は通常権限の開発環境から実行確認していない。

管理者PowerShellでこのフォルダーに移動し、実行する：

```powershell
powershell -ExecutionPolicy Bypass -File .\enable-auditing.ps1
npm start
```

起動済みのアプリは Ctrl+C で終了してから管理者として再起動。スクリプトは全Firewallプロファイルの許可・遮断ログとログオン・ログオフ・プロセス作成監査を有効化する。ポート開放やFirewall規則変更は行わない。変更前の監査ポリシーは `data/audit-policy-before.csv` に保存。組織のグループポリシーで上書きされる場合がある。

通常はプロセス名のみ記録。引数も必要な場合：

```powershell
powershell -ExecutionPolicy Bypass -File .\enable-auditing.ps1 -CommandLine
```

**コマンド引数のパスワードやトークンもSecurityログに記録される場合がある。** 必要な場合のみ有効化。無効化：

```powershell
Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 0
```

監視設定の公開IPは表示用。未指定でもこのPCを監視する。IPによる別ホストへの切り替え機能ではない。

## 地図とデータ

- GeoIPは初期状態で無効。有効化すると送信元の公開IPを [ipwho.is](https://ipwho.is/) に送り推定位置を取得（最大5IP / 30秒、アプリ内上限900リクエスト / UTC日、失敗時1時間後に再試行）。位置不明のIPも件数・ログに残る。VPN・プロキシの出口位置の場合がある。提供元の制限・通信エラー時は位置未取得のまま表示する。
- 地図は [world.geo.json](https://github.com/johan/world.geo.json) の国境データ（Natural Earth由来）を同梱。地図タイルへの外部接続なし。
- イベント・設定・位置キャッシュは `data/` に保存しGit対象外。ログ保存にはユーザー名・コマンドなどを含む。
- サーバーは `127.0.0.1:4317` のみにバインド。同一PCでの利用を想定。ローカルの他ユーザーに対するアクセス制御は提供しない。

## 件数の意味と取得範囲

1. **外部アクセス記録**＝Firewallに記録された外部送信元の受信パケット数。接続数・HTTPリクエスト数・攻撃回数ではない。同一ログ行は重複排除するため、同秒・同内容の記録は過少計数の場合がある。
2. **リモート認証成功**＝Security 4624のLogon Type 3（ネットワーク）/ 10（RDP）。正規利用を含み、不正侵入の確定ではない。失敗は4625。プライベートIP・ループバック・CGNATなどは除外。内部VPN経由の認証も集計されない場合がある。
3. **認証後の操作**＝リモート認証のログオンIDと4688の実行コンテキストを関連付けたプロセス作成。4634の後は関連付けない。24時間より前・未取得の認証、サービス経由の操作、ファイル変更、全PowerShellスクリプトなどは網羅しない。認証不要の脆弱性悪用も検出を保証しない。
4. **確認済みの侵入**＝このアプリ単独では判定不可。認証成功・操作内容を調査するための表示。架空の侵入件数は表示しない。
5. **範囲と保持**＝このPCに到達した通信のみ。ルーターで遮断された通信には別途ルーターログが必要。過去の未記録データは復元不可。30秒ごとに直近24時間のSecurity（最大20,000件）とFirewall末尾20,000行を読む。7日間 / 最大50,000件を保持。高負荷・長時間停止・ログローテーション時の完全収集は保証しない。上限到達は画面表示。GeoIPキャッシュは別に保持。

## 検証

`npm test` で外部IP除外、Firewall受信判定、認証とプロセスの関連付けを確認。

参考：[4624](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624)、[4688](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688)、[Firewall記録](https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/configure-logging)。
