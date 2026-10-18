param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$InstallDirectory = '.panbox/bin'
)
$ErrorActionPreference = 'Stop'
if ($Version -notmatch '^v[0-9][A-Za-z0-9._-]*$') { throw 'Expected a pinned release tag such as v0.1.0-alpha.8' }
$architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
if ($architecture -notin @('x64', 'arm64')) { throw "Unsupported CPU architecture: $architecture" }
$arch = if ($architecture -eq 'x64') { 'amd64' } else { 'arm64' }
$asset = "panbox-agent_windows_$arch.exe"
$base = "https://github.com/alterwriter/PANBOX/releases/download/$Version"
$temporary = Join-Path ([System.IO.Path]::GetTempPath()) ("panbox-install-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
    $agentPath = Join-Path $temporary $asset
    $checksumsPath = Join-Path $temporary 'SHA256SUMS'
    Invoke-WebRequest -Uri "$base/$asset" -OutFile $agentPath
    Invoke-WebRequest -Uri "$base/SHA256SUMS" -OutFile $checksumsPath
    $line = Get-Content -LiteralPath $checksumsPath | Where-Object { $_ -match ("^[a-fA-F0-9]{64}\s+" + [regex]::Escape($asset) + '$') } | Select-Object -First 1
    if (-not $line) { throw "Release checksum for $asset is missing" }
    $expected = ($line -split '\s+')[0]
    $actual = (Get-FileHash -LiteralPath $agentPath -Algorithm SHA256).Hash
    if ($actual -ne $expected) { throw "Checksum mismatch for $asset" }
    New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
    Copy-Item -LiteralPath $agentPath -Destination (Join-Path $InstallDirectory 'panbox.exe') -Force
    Write-Output "Installed PANBOX agent $Version at $(Join-Path $InstallDirectory 'panbox.exe')"
} finally {
    if (Test-Path -LiteralPath $agentPath) { Remove-Item -LiteralPath $agentPath -Force }
    if (Test-Path -LiteralPath $checksumsPath) { Remove-Item -LiteralPath $checksumsPath -Force }
    Remove-Item -LiteralPath $temporary -Force
}
