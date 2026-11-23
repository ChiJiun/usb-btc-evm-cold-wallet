#requires -Version 5.1
<#
Read-only physical USB discovery. A caller must independently obtain and pin
the expected manifest SHA-256, source commit and raw image SHA-256.
Result NEVER denotes completed physical/GUI/E2E acceptance.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z]:?$')][string]$DriveLetter,
    [string]$ImagePath,
    [string]$ExpectedSha256,
    [string]$ExpectedCommit,
    [string]$LayoutManifest,
    [string]$ExpectedManifestSha256,
    [switch]$VerifyMediaReadback,
    [switch]$Json
)
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'physical_usb_inventory_core.psm1') -Force

function Normalize-Guid([string]$Value) { return $Value.Trim('{}').ToLowerInvariant() }
function Read-ExactAt([System.IO.Stream]$Stream, [long]$Offset, [int]$Count) {
    [void]$Stream.Seek($Offset, [System.IO.SeekOrigin]::Begin)
    $buffer = New-Object byte[] $Count
    $read = 0
    while ($read -lt $Count) {
        $n = $Stream.Read($buffer, $read, $Count - $read)
        if ($n -le 0) { throw 'Truncated read-only physical media sector' }
        $read += $n
    }
    return ,$buffer
}
function Read-FatIdentity([System.IO.Stream]$Stream, [long]$Offset) {
    $sector = Read-ExactAt $Stream $Offset 512
    if ($sector[510] -ne 0x55 -or $sector[511] -ne 0xAA -or
        [BitConverter]::ToUInt16($sector, 11) -ne 512) {
        throw 'Invalid FAT boot sector at partition offset'
    }
    $ascii = [System.Text.Encoding]::ASCII
    $fat32 = $ascii.GetString($sector, 82, 8) -eq 'FAT32   '
    $type = if ($fat32) { 'FAT32' } else { $ascii.GetString($sector, 54, 8).TrimEnd() }
    if (@('FAT12','FAT16','FAT32') -notcontains $type) { throw 'Unsupported FAT type on media' }
    $labelOffset = if ($fat32) { 71 } else { 43 }
    $label = $ascii.GetString($sector, $labelOffset, 11).TrimEnd()
    return @{ label = $label; filesystem = if ($fat32) { 'FAT32' } else { 'FAT' } }
}
function Hash-Prefix([System.IO.Stream]$Stream, [long]$Bytes) {
    if ($Bytes -le 0 -or $Bytes -gt 1073741824) { throw 'Unsafe media readback length' }
    [void]$Stream.Seek(0, [System.IO.SeekOrigin]::Begin)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $buffer = New-Object byte[] 1048576
    try {
        $remaining = $Bytes
        while ($remaining -gt 0) {
            $count = [int][Math]::Min($remaining, $buffer.Length)
            $n = $Stream.Read($buffer, 0, $count)
            if ($n -le 0) { throw 'Truncated read-only physical media image' }
            [void]$sha.TransformBlock($buffer, 0, $n, $buffer, 0)
            $remaining -= $n
        }
        [void]$sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
        return [BitConverter]::ToString($sha.Hash).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}
function Collect-Snapshot([string]$Letter) {
    $target = @(Get-Partition -DriveLetter $Letter -ErrorAction Stop)
    if ($target.Count -ne 1) { throw 'Ambiguous drive-letter mapping' }
    $disk = Get-Disk -Number $target[0].DiskNumber -ErrorAction Stop
    $partitions = @(Get-Partition -DiskNumber $disk.Number -ErrorAction Stop | Sort-Object PartitionNumber)
    if ($target[0].PartitionNumber -ne 3 -or [string]$target[0].DiskNumber -ne [string]$disk.Number) {
        throw 'Drive letter does not belong to partition 3 of its parent disk'
    }
    $parts = @()
    foreach ($p in $partitions) {
        $vol = $p | Get-Volume -ErrorAction SilentlyContinue
        $parts += [pscustomobject]@{
            diskNumber = [int]$p.DiskNumber
            partitionNumber = [int]$p.PartitionNumber
            partitionGuid = [string]$p.Guid
            gptType = [string]$p.GptType
            offsetBytes = [long]$p.Offset
            sizeBytes = [long]$p.Size
            driveLetter = if ($p.DriveLetter) { ([string]$p.DriveLetter).ToUpperInvariant() } else { '' }
            label = if ($vol) { [string]$vol.FileSystemLabel } else { '' }
            filesystem = if ($vol) { [string]$vol.FileSystem } else { '' }
        }
    }
    $peers = @()
    foreach ($other in @(Get-Disk -ErrorAction Stop | Where-Object { $_.BusType -eq 'USB' })) {
        if ($other.Number -eq $disk.Number) { continue }
        $otherParts = @(Get-Partition -DiskNumber $other.Number -ErrorAction Stop)
        $otherLabels = @()
        foreach ($p in $otherParts) {
            $v = $p | Get-Volume -ErrorAction SilentlyContinue
            if ($v) { $otherLabels += [string]$v.FileSystemLabel }
        }
        $peers += [pscustomobject]@{
            diskNumber = [int]$other.Number
            diskGuid = [string]$other.Guid
            model = [string]$other.FriendlyName
            labels = @($otherLabels)
            partitionGuids = @($otherParts | ForEach-Object { [string]$_.Guid })
        }
    }
    return [pscustomobject]@{
        driveLetter = $Letter
        disk = [pscustomobject]@{
            diskNumber = [int]$disk.Number
            diskGuid = [string]$disk.Guid
            model = [string]$disk.FriendlyName
            busType = [string]$disk.BusType
            sizeBytes = [long]$disk.Size
            logicalSectorSize = [int]$disk.LogicalSectorSize
            partitionStyle = [string]$disk.PartitionStyle
        }
        partitions = @($parts)
        peers = @($peers)
    }
}
try {
    $letter = $DriveLetter.Substring(0,1).ToUpperInvariant()
    $snapshot = Collect-Snapshot $letter
    $fileVerified = $false
    $layoutVerified = $false
    $readbackVerified = $false
    $checks = @()
    $manifest = $null
    $rawHash = $null
    $mediaHash = $null
    if (-not $LayoutManifest -or -not $ExpectedManifestSha256 -or
        -not $ExpectedCommit -or -not $ExpectedSha256 -or -not $ImagePath) {
        $checks += 'Required exact image/commit/manifest evidence missing'
    } else {
        if ($ExpectedManifestSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
            $ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$' -or
            $ExpectedCommit -notmatch '^[0-9a-fA-F]{40}$') { throw 'Invalid exact verification input' }
        if ((Get-FileHash -LiteralPath $LayoutManifest -Algorithm SHA256).Hash -ne $ExpectedManifestSha256) {
            throw 'Untrusted layout manifest hash'
        }
        $manifest = Get-Content -LiteralPath $LayoutManifest -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([string]$manifest.sourceCommit -ne $ExpectedCommit -or
            [string]$manifest.imageSha256 -ne $ExpectedSha256) {
            throw 'Exact source commit/raw image manifest binding mismatch'
        }
        $file = Get-Item -LiteralPath $ImagePath -ErrorAction Stop
        if ($file.PSIsContainer -or [long]$file.Length -ne [long]$manifest.imageSizeBytes) {
            throw 'Raw image file length mismatch'
        }
        $rawHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($rawHash -ne $ExpectedSha256.ToLowerInvariant()) {
            $checks += 'Image file SHA-256 mismatch'
        } else {
            $fileVerified = $true
        }
        if ($VerifyMediaReadback -and $fileVerified) {
            # PhysicalDriveN is used only after fresh drive letter -> partition ->
            # USB parent discovery, never as a stored target or for write access.
            $path = '\\.\PhysicalDrive' + [string]$snapshot.disk.diskNumber
            $stream = [System.IO.FileStream]::new($path, [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            try {
                $mediaHash = Hash-Prefix $stream ([long]$manifest.imageSizeBytes)
                if ($mediaHash -ne $rawHash) { throw 'Flashed physical media readback SHA-256 mismatch' }
                foreach ($p in @($snapshot.partitions)) {
                    $fat = Read-FatIdentity $stream ([long]$p.offsetBytes)
                    if ($p.label -and [string]$p.label -cne [string]$fat.label) {
                        throw 'Windows reported volume label differs from physical media'
                    }
                    if ($p.filesystem -and [string]$p.filesystem -ne [string]$fat.filesystem) {
                        throw 'Windows reported filesystem differs from physical media'
                    }
                    $p.label = [string]$fat.label
                    $p.filesystem = [string]$fat.filesystem
                }
            } finally { $stream.Dispose() }
            $after = Collect-Snapshot $letter
            # Do not accept an unplug/replug, changed letter/parent or altered
            # partition identity between the raw read and the new enumeration.
            foreach ($i in 0..2) {
                if ($after.partitions.Count -ne 3 -or
                    $after.partitions[$i].partitionGuid -ne $snapshot.partitions[$i].partitionGuid -or
                    $after.partitions[$i].offsetBytes -ne $snapshot.partitions[$i].offsetBytes -or
                    $after.partitions[$i].sizeBytes -ne $snapshot.partitions[$i].sizeBytes) {
                    throw 'Device replacement or layout change during readback'
                }
            }
            if ($after.disk.diskNumber -ne $snapshot.disk.diskNumber -or
                $after.disk.diskGuid -ne $snapshot.disk.diskGuid -or
                $after.disk.busType -ne $snapshot.disk.busType) {
                throw 'USB parent changed during readback'
            }
            $readbackVerified = $true
        } else {
            $checks += 'Read-only physical media readback NOT TESTED'
        }
        $result = Test-PhysicalInventorySnapshot -Snapshot $snapshot -Manifest $manifest
        $layoutVerified = [bool]$result.deviceLayoutVerified
        $checks += @($result.reasons)
    }
    $status = if ($checks | Where-Object { $_ -match 'mismatch|changed|Wrong|Duplicate|Ambiguous' }) { 'FAIL' } elseif (
        $layoutVerified -and $fileVerified -and $readbackVerified) { 'INVENTORY_VERIFIED' } else { 'BLOCKED' }
    $out = [ordered]@{
        schemaVersion = 2
        collectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        imageFileVerified = $fileVerified
        deviceLayoutVerified = $layoutVerified
        writtenMediaVerified = $readbackVerified
        imageSha256 = $rawHash
        mediaReadbackSha256 = $mediaHash
        exactImageCommit = $ExpectedCommit
        observed = $snapshot
        physicalAcceptance = 'NOT TESTED'
        result = $status
        reasons = @($checks)
    }
    $out | ConvertTo-Json -Depth 12
    if ($status -eq 'INVENTORY_VERIFIED') { exit 0 }
    if ($status -eq 'FAIL') { exit 2 }
    exit 3
} catch {
    [ordered]@{ schemaVersion=2; result='BLOCKED'; physicalAcceptance='NOT TESTED';
        imageFileVerified=$false; deviceLayoutVerified=$false; writtenMediaVerified=$false;
        reason=$_.Exception.Message } | ConvertTo-Json -Depth 4
    exit 3
}
