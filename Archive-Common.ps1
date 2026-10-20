Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Find-SevenZip {
    $command = Get-Command 7z.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($base) {
            $candidate = Join-Path $base '7-Zip\7z.exe'
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        }
    }
    throw '7-Zip was not found. Install 7-Zip before running this tool.'
}

function Get-WindowsFilePath([string]$Path) {
    if ($Path.StartsWith('\\?\')) { return $Path }
    if ($Path.StartsWith('\\')) { return '\\?\UNC\' + $Path.Substring(2) }
    return '\\?\' + [IO.Path]::GetFullPath($Path)
}

function Get-ChildPath([string]$Root, [string]$Relative) {
    if ([IO.Path]::IsPathRooted($Relative) -or $Relative -match '(^|[\\/])\.\.?([\\/]|$)' -or $Relative.Contains(':')) {
        throw 'Invalid relative path.'
    }
    $boundary = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $target = [IO.Path]::GetFullPath((Join-Path $boundary $Relative))
    if (-not $target.StartsWith($boundary + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Path escapes the selected directory.'
    }
    $cursor = $target
    while ($true) {
        if (Test-Path -LiteralPath (Get-WindowsFilePath $cursor)) {
            if ((Get-Item -LiteralPath (Get-WindowsFilePath $cursor) -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw 'Linked paths are not supported.'
            }
        }
        if ($cursor -eq $boundary) { break }
        $cursor = Split-Path -Parent $cursor
    }
    return $target
}

function ConvertTo-NativeArgument([string]$Value) {
    # Quote Windows native argv; no shell is used and no password is put in argv.
    '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}

function Invoke-SevenZip {
    param([string]$Exe, [string[]]$Arguments, [string]$WorkingDirectory,
          [Security.SecureString]$Password)
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Exe
    $start.Arguments = (($Arguments | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' ')
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
    $start.StandardErrorEncoding = New-Object Text.UTF8Encoding($false)
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if ($Password) {
            $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
            $buffer = $null
            try {
                $buffer = [Text.Encoding]::UTF8.GetBytes([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) + "`n")
                $process.StandardInput.BaseStream.Write($buffer, 0, $buffer.Length)
                $process.StandardInput.BaseStream.Flush()
            }
            finally {
                if ($buffer) { [Array]::Clear($buffer, 0, $buffer.Length) }
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
            }
        }
        $process.StandardInput.Close()
        $process.WaitForExit()
        $output = $stdout.GetAwaiter().GetResult()
        $errors = $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) { throw "7-Zip failed ($($process.ExitCode)). $errors $output" }
        return $output
    }
    finally { $process.Dispose() }
}

function Write-JsonFile([string]$Path, $Value) {
    if (Test-Path -LiteralPath $Path) { throw "Refusing to overwrite: $Path" }
    [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 30), (New-Object Text.UTF8Encoding($false)))
}

function Assert-FileRecord([string]$Root, $Record) {
    $file = Get-WindowsFilePath (Get-ChildPath $Root $Record.path)
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing file: $($Record.path)" }
    if ((Get-Item -LiteralPath $file).Length -ne [long]$Record.bytes) { throw "Size mismatch: $($Record.path)" }
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Record.sha256) {
        throw "SHA256 mismatch: $($Record.path)"
    }
}

function Read-TransportIndex([string]$Root) {
    $index = Get-Content -LiteralPath (Get-ChildPath $Root 'package-index.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($index.schema -ne 'WMS_GITHUB_SPLIT_V1' -or $index.volume_bytes -ne 99000000) {
        throw 'Unsupported transport package.'
    }
    $opaque = ($index.PSObject.Properties.Name -contains 'opaque_names') -and $index.opaque_names
    $groupPattern = if ($opaque) { '^[a-f0-9]{32}$' } else { '^[0-9]{2}-[a-z0-9-]+$' }
    foreach ($group in $index.groups) {
        if ($group.id -notmatch $groupPattern) { throw 'Invalid group identifier.' }
        foreach ($part in $group.parts) {
            if ($part.path -notmatch ('^packages/' + [regex]::Escape($group.id) + '\.7z\.[0-9]{3,}$')) {
                throw 'Invalid inner volume name.'
            }
            if ($part.bytes -ge 100000000) { throw 'An inner volume exceeds 100 MB.' }
        }
        $records = if ($index.encrypted) { $group.encrypted_parts } else { $group.parts }
        foreach ($part in $records) {
            if ($opaque -and $part.path -notmatch ('^packages/' + [regex]::Escape($group.id) + '\.7z\.[0-9]{3,}$')) {
                throw 'Invalid opaque volume name.'
            }
            if ($part.bytes -ge 100000000) { throw 'A volume exceeds 100 MB.' }
            Assert-FileRecord $Root $part
        }
    }
    return $index
}

function Get-DecryptedInnerArchive([string]$Work, $Group, [bool]$Opaque) {
    if (-not $Opaque) {
        foreach ($part in $Group.parts) {
            Assert-FileRecord $Work ([pscustomobject]@{path=(Split-Path -Leaf $part.path); bytes=$part.bytes; sha256=$part.sha256})
        }
        return Get-ChildPath $Work (Split-Path -Leaf $Group.parts[0].path)
    }
    # The original inner names are only available after password-based decryption.
    $files = @(Get-ChildItem -LiteralPath (Get-WindowsFilePath $Work) -File)
    if ($files.Count -ne @($Group.parts).Count) { throw 'Unexpected inner volume count.' }
    $first = $null
    foreach ($part in $Group.parts) {
        $suffix = [IO.Path]::GetExtension($part.path)
        $match = @($files | Where-Object { $_.Name -match ('\.7z' + [regex]::Escape($suffix) + '$') })
        if ($match.Count -ne 1) { throw 'Missing or duplicate inner volume ordinal.' }
        Assert-FileRecord $Work ([pscustomobject]@{path=$match[0].Name; bytes=$part.bytes; sha256=$part.sha256})
        if ($part.path -eq $Group.parts[0].path) { $first = Get-ChildPath $Work $match[0].Name }
    }
    return $first
}

function Read-ArchivePassword([switch]$Confirm) {
    $first = Read-Host 'Password (hidden)' -AsSecureString
    if ($first.Length -eq 0) { $first.Dispose(); throw 'An empty password is not allowed.' }
    if ($Confirm) {
        $second = Read-Host 'Repeat password (hidden)' -AsSecureString
        $left = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($first)
        $right = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($second)
        try {
            if ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($left) -cne [Runtime.InteropServices.Marshal]::PtrToStringBSTR($right)) {
                $first.Dispose()
                throw 'Passwords did not match.'
            }
        }
        finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($left)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($right)
            $second.Dispose()
        }
    }
    return $first
}

function Remove-OwnedWorkDirectory([string]$Root, [string]$Relative) {
    $target = Get-WindowsFilePath (Get-ChildPath $Root $Relative)
    # Only our exact temporary directory is eligible for recursive removal.
    if ($Relative -ne '_transport_work') { throw 'Unexpected cleanup target.' }
    foreach ($item in Get-ChildItem -LiteralPath $target -Force -Recurse) {
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked cleanup item.' }
    }
    Remove-Item -LiteralPath $target -Recurse -Force
}

function New-EncryptedTransport {
    param([string]$Source, [string]$Destination, [Security.SecureString]$Password, [string]$SevenZip)
    if (-not $Password -or $Password.Length -eq 0) { throw 'An encryption password is required.' }
    $index = Read-TransportIndex $Source
    if ($index.encrypted) { throw 'This package is already encrypted.' }
    if (Test-Path -LiteralPath $Destination) { throw 'Choose a new destination directory.' }
    $Destination = [IO.Path]::GetFullPath($Destination)
    $required = ($index.groups | ForEach-Object { $_.parts } | Measure-Object bytes -Sum).Sum + 2GB
    if ((New-Object IO.DriveInfo([IO.Path]::GetPathRoot($Destination))).AvailableFreeSpace -lt $required) {
        throw 'Not enough free space for the encrypted copy plus 2 GiB.'
    }
    [void](New-Item -ItemType Directory -Path $Destination)
    [void](New-Item -ItemType Directory -Path (Get-ChildPath $Destination 'packages'))
    $work = Get-ChildPath $Destination '_transport_work'
    [void](New-Item -ItemType Directory -Path $work)
    $position = 0
    foreach ($group in $index.groups) {
        $position++
        Write-Host "Encrypting $position/$($index.groups.Count): $($group.id)"
        $list = Get-ChildPath $work ($group.id + '.txt')
        $names = @($group.parts | ForEach-Object { Split-Path -Leaf $_.path })
        [IO.File]::WriteAllLines($list, $names, (New-Object Text.UTF8Encoding($false)))
        $archive = Get-ChildPath $Destination ("packages/" + $group.id + '-encrypted.7z')
        $arguments = @('a', '-t7z', '-m0=Copy', '-mhe=on', '-p', '-v99000000b',
                       '-scsUTF-8', '-sccUTF-8', '-bsp0', $archive, ('@' + $list))
        [void](Invoke-SevenZip $SevenZip $arguments (Get-ChildPath $Source 'packages') $Password)
        $head = $archive + '.001'
        $test = Invoke-SevenZip $SevenZip @('t', '-sccUTF-8', '-bsp0', $head) $Destination $Password
        if ($test -notmatch '7zAES') { throw 'Encryption verification failed.' }
        $parts = @(Get-ChildItem -LiteralPath (Get-ChildPath $Destination 'packages') -File |
            Where-Object { $_.Name.StartsWith($group.id + '-encrypted.7z.') } | Sort-Object Name |
            ForEach-Object {
                if ($_.Length -ge 100000000) { throw 'Encrypted volume exceeds 100 MB.' }
                [ordered]@{path=('packages/' + $_.Name); bytes=$_.Length; sha256=(Get-FileHash -LiteralPath $_.FullName).Hash.ToLowerInvariant()}
            })
        $group | Add-Member -NotePropertyName encrypted_parts -NotePropertyValue $parts
    }
    $index.encrypted = $true
    Write-JsonFile (Get-ChildPath $Destination 'package-index.json') $index
    foreach ($name in @('Restore.cmd', 'Restore.ps1', 'Archive-Common.ps1', 'README.md')) {
        Copy-Item -LiteralPath (Get-ChildPath $Source $name) -Destination (Get-ChildPath $Destination $name)
    }
    Remove-OwnedWorkDirectory $Destination '_transport_work'
    Write-JsonFile (Get-ChildPath $Destination 'encryption-complete.json') ([ordered]@{
        status='PASS'; encrypted=$true; password_saved=$false; headers_encrypted=$true;
        strict_file_limit=100000000; created_at=[DateTime]::UtcNow.ToString('o')
    })
}

function Restore-Transport {
    param([string]$Source, [string]$Destination, [Security.SecureString]$Password, [string]$SevenZip)
    $index = Read-TransportIndex $Source
    $opaque = ($index.PSObject.Properties.Name -contains 'opaque_names') -and $index.opaque_names
    if ($index.encrypted -and (-not $Password -or $Password.Length -eq 0)) {
        throw 'A decryption password is required.'
    }
    if (Test-Path -LiteralPath $Destination) { throw 'Choose a new restore directory.' }
    $Destination = [IO.Path]::GetFullPath($Destination)
    if ((New-Object IO.DriveInfo([IO.Path]::GetPathRoot($Destination))).AvailableFreeSpace -lt ($index.expanded_bytes + 2GB)) {
        throw 'Not enough free space for restoration plus 2 GiB.'
    }
    [void](New-Item -ItemType Directory -Path $Destination)
    foreach ($group in $index.groups) {
        Write-Host "Restoring $($group.id)"
        if ($index.encrypted) {
            $work = Get-ChildPath $Destination '_transport_work'
            [void](New-Item -ItemType Directory -Path $work)
            $encrypted = Get-ChildPath $Source $group.encrypted_parts[0].path
            [void](Invoke-SevenZip $SevenZip @('x', '-y', '-sccUTF-8', '-bsp0', ('-o' + $work), $encrypted) $Source $Password)
            $head = Get-DecryptedInnerArchive $work $group $opaque
        }
        else { $head = Get-ChildPath $Source $group.parts[0].path }
        [void](Invoke-SevenZip $SevenZip @('x', '-y', '-sccUTF-8', '-bsp0', ('-o' + $Destination), $head) $Source)
        if ($index.encrypted) { Remove-OwnedWorkDirectory $Destination '_transport_work' }
    }
    $manifestPath = Get-ChildPath $Destination 'package_manifest.json'
    if ((Get-FileHash -LiteralPath $manifestPath).Hash.ToLowerInvariant() -ne $index.source_manifest_sha256) {
        throw 'The restored package manifest differs from the sealed source.'
    }
    $original = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($record in $original.files) { Assert-FileRecord $Destination $record }
    $count = @(Get-ChildItem -LiteralPath (Get-WindowsFilePath $Destination) -Recurse -Force -File).Count
    if ($count -ne $index.source_files) { throw 'Restored file count differs from the sealed source.' }
    Write-Host "PASS: restored and verified $count files."
}
