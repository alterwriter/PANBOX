param(
  [string]$AdminEmail = 'admin@panbox.local',
  [int]$HostPort = 8080,
  [int]$DBPort = 5434
)
$ErrorActionPreference = 'Stop'
$target = Join-Path $PSScriptRoot '..\.env'
if (Test-Path -LiteralPath $target) { throw '.env already exists; edit it explicitly instead of regenerating credentials.' }
function New-Secret {
  $bytes = [byte[]]::new(32)
  [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
  return [Convert]::ToHexString($bytes).ToLowerInvariant()
}
$db = New-Secret
$admin = New-Secret
$lines = @(
  "PANBOX_DB_PASSWORD=$db",
  "PANBOX_BOOTSTRAP_EMAIL=$AdminEmail",
  "PANBOX_BOOTSTRAP_PASSWORD=$admin",
  'PANBOX_SECURE_COOKIE=false',
  "PANBOX_HOST_PORT=$HostPort",
  "PANBOX_DB_HOST_PORT=$DBPort"
)
[System.IO.File]::WriteAllLines($target, $lines)
Write-Host "Created $target with random local credentials. Keep this file private."
