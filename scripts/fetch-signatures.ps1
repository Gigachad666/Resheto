param(
    [Parameter(Mandatory=$true)][string]$Output,
    [ValidatePattern('^[0-9a-f]{40}$')][string]$Revision='9e6be541abb33859f49c06d66cf7c97e54ab2bc4'
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
if (Test-Path -LiteralPath $Output) { throw 'Выберите новый каталог -- снимок не перезаписывается' }
New-Item -ItemType Directory -Path $Output | Out-Null
$base="https://raw.githubusercontent.com/romainmarcoux/malicious-hash/$Revision"
# Только опубликованный список digest и сведения об источнике; образцы не загружаются.
Invoke-WebRequest "$base/full-hash-sha256-aa.txt" -OutFile (Join-Path $Output 'full-hash-sha256-aa.txt')
Invoke-WebRequest "$base/LICENSE" -OutFile (Join-Path $Output 'LICENSE')
Invoke-WebRequest "$base/README.md" -OutFile (Join-Path $Output 'README.upstream.md')
$provenance=[ordered]@{
    source_url="$base/full-hash-sha256-aa.txt"
    source_revision=$Revision
    source_sha256=(Get-FileHash (Join-Path $Output 'full-hash-sha256-aa.txt') -Algorithm SHA256).Hash.ToLowerInvariant()
    acquired_utc=[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    license='MIT'
    license_url="$base/LICENSE"
    attribution='Copyright (c) 2025 Romain MARCOUX; malicious-hash aggregate feed'
    limitations='Агрегатор не предоставляет семейства, размер, время и первоисточник отдельного SHA-256. Только HASH; без PATTERN.'
}
Save-ReshetoUtf8 ([IO.Path]::GetFullPath((Join-Path $Output 'provenance.json'))) ($provenance | ConvertTo-Json)
Write-Output "Сохранён снимок $Revision; проверьте LICENSE перед импортом."
