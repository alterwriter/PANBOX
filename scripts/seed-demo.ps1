param(
  [string]$BaseUrl = 'http://127.0.0.1:8080',
  [string]$Email = 'admin@example.com'
)
$ErrorActionPreference = 'Stop'
if ($env:PANBOX_BOOTSTRAP_PASSWORD) { $password = $env:PANBOX_BOOTSTRAP_PASSWORD }
else { $secure = Read-Host 'PANBOX admin password' -AsSecureString; $password = [System.Net.NetworkCredential]::new('', $secure).Password }
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$login = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/auth/login" -WebSession $session -ContentType 'application/json' -Body (@{ email=$Email; password=$password } | ConvertTo-Json)
$headers = @{ 'X-CSRF-Token' = $login.csrf_token }
$repos = @(
  @{ name='alpha-api'; project='900001'; fixture='repo-alpha-main.json'; feature='repo-alpha-feature.json' },
  @{ name='beta-web'; project='900002'; fixture='repo-beta-main.json'; feature='repo-beta-feature-partial.json' }
)
foreach ($entry in $repos) {
  $body = @{ name=$entry.name; provider='gitlab'; provider_project_id=$entry.project; default_branch='main'; owner='Demo' } | ConvertTo-Json
  try { $repo = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/repos" -WebSession $session -Headers $headers -ContentType 'application/json' -Body $body }
  catch { $repo = (Invoke-RestMethod -Uri "$BaseUrl/v1/repos" -WebSession $session) | Where-Object { $_.provider_project_id -eq $entry.project } | Select-Object -First 1 }
  if (-not $repo.id) { throw "Could not enroll $($entry.name)" }
  $token = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/repos/$($repo.id)/scan-tokens" -WebSession $session -Headers $headers -ContentType 'application/json' -Body '{"label":"demo-seed","expires_hours":24}'
  foreach ($file in @($entry.fixture, $entry.feature)) {
    $json = (Get-Content -LiteralPath (Join-Path $PSScriptRoot "../test/fixtures/$file") -Raw).Replace("REPLACE_$($entry.name.Split('-')[0].ToUpper())_ID", $repo.id)
    $null = Invoke-RestMethod -Method Post -Uri "$BaseUrl/v1/scans" -Headers @{ Authorization="Bearer $($token.secret)" } -ContentType 'application/json' -Body $json
  }
  Write-Host "Seeded $($entry.name): $($repo.id)"
}
Write-Host 'Demo scans loaded. Refresh PANBOX Overview.'
