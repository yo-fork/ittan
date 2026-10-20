param([string]$Destination = '')
. (Join-Path $PSScriptRoot 'Archive-Common.ps1')
try {
    if (-not $Destination) { $Destination = Join-Path $PSScriptRoot ('WMS-Restored-' + (Get-Date -Format 'yyyyMMdd-HHmmss')) }
    $exe = Find-SevenZip
    $metadata = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'package-index.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $password = $null
    if ($metadata.encrypted) { $password = Read-ArchivePassword }
    try { Restore-Transport $PSScriptRoot $Destination $password $exe }
    finally { if ($password) { $password.Dispose() } }
    Write-Host "Open $Destination\Run.cmd to use the restored package."
}
catch { Write-Error $_; exit 1 }
