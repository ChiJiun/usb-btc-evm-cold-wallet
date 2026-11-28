#requires -Version 5.1
<#
Pure verification logic. The caller supplies a freshly discovered Windows snapshot
and an independently SHA-256-verified manifest for an exact #76 image.
No disk is opened, mutated, signed or broadcast by this module; stream hashing
only reads a stream the caller already opened read-only.
#>
Set-StrictMode -Version Latest

function Test-PhysicalInventorySnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][object]$Snapshot,
        [Parameter(Mandatory=$true)][object]$Manifest
    )
    $failure = New-Object 'System.Collections.Generic.List[string]'
    $guidRegex = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $guid = {
        param($value)
        if ($null -eq $value) { return '' }
        return ([string]$value).Trim('{}').ToLowerInvariant()
    }
    try {
        if ([int]$Manifest.schemaVersion -ne 1 -or [string]$Manifest.layout -ne 'single-usb-issue-37') {
            throw 'Unsupported image layout manifest'
        }
        if ([string]$Manifest.sourceCommit -notmatch '^[0-9a-fA-F]{40}$' -or
            [string]$Manifest.imageSha256 -notmatch '^[0-9a-fA-F]{64}$') {
            throw 'Manifest must bind an exact commit and complete raw image hash'
        }
        $imageLength = [long]$Manifest.imageSizeBytes
        if ($imageLength -le 0 -or $imageLength -gt 1073741824) {
            throw 'Image size exceeds readback bound (1 GiB)'
        }
        $mDisk = & $guid $Manifest.diskGuid
        if ($mDisk -notmatch $guidRegex) { throw 'Missing expected disk GUID' }
        $d = $Snapshot.disk
        if ($null -eq $d -or [string]$d.busType -ne 'USB' -or [string]$d.partitionStyle -ne 'GPT') {
            throw 'Selected parent is not a GPT USB physical disk'
        }
        if ((& $guid $d.diskGuid) -ne $mDisk) { throw 'Wrong physical disk GUID' }
        if ([long]$d.sizeBytes -lt $imageLength -or [int]$d.logicalSectorSize -ne 512) {
            throw 'Physical disk too small or unexpected logical sector size'
        }
        if ([string]$Manifest.model -and [string]$Manifest.model -ne [string]$d.model) {
            throw 'Physical disk model does not match expected model'
        }
        $parts = @($Snapshot.partitions)
        $expected = @($Manifest.partitions)
        if ($parts.Count -ne 3 -or $expected.Count -ne 3) {
            throw 'Exactly three partitions are required'
        }
        $seenGuid = @{}
        $seenLabels = @{}
        for ($i = 0; $i -lt 3; $i++) {
            $p = $parts[$i]
            $e = $expected[$i]
            $partId = & $guid $p.partitionGuid
            if ($partId -notmatch $guidRegex -or $seenGuid.ContainsKey($partId)) {
                throw 'Missing or duplicated partition unique GUID'
            }
            $seenGuid[$partId] = $true
            if ([int]$p.diskNumber -ne [int]$d.diskNumber -or
                [int]$p.partitionNumber -ne ($i + 1) -or
                [int]$e.partitionNumber -ne ($i + 1) -or
                $partId -ne (& $guid $e.partitionGuid) -or
                (& $guid $p.gptType) -ne (& $guid $e.gptType) -or
                [long]$p.offsetBytes -ne [long]$e.offsetBytes -or
                [long]$p.sizeBytes -ne [long]$e.sizeBytes) {
                throw "Partition $($i+1) GUID/type/geometry/parent mismatch"
            }
            if (-not [string]$p.label -or -not [string]$p.filesystem) {
                throw "Partition $($i+1) FAT label/filesystem unavailable (run with -VerifyMediaReadback)"
            }
            if ([string]$p.label -cne [string]$e.label -or
                [string]$p.filesystem -ne [string]$e.filesystem) {
                throw "Partition $($i+1) FAT label/filesystem mismatch"
            }
            if ($seenLabels.ContainsKey([string]$p.label)) { throw 'Duplicate partition labels' }
            $seenLabels[[string]$p.label] = $true
            if ($i -lt 2 -and [string]$p.driveLetter) {
                throw 'EFI/Vault unexpectedly has a Windows drive letter'
            }
            if ($i -eq 2 -and
                (([string]$p.driveLetter).ToUpperInvariant() -ne ([string]$Snapshot.driveLetter).ToUpperInvariant() -or
                 [string]$p.label -cne 'TX_TRANSFER')) {
                throw 'Drive letter does not resolve to the actual TX_TRANSFER partition'
            }
        }
        # Reject a replica with the same GPT GUID, or any second USB that
        # advertises the same transfer label/model. Disk/letter numbers are ephemeral.
        foreach ($peer in @($Snapshot.peers)) {
            if ([int]$peer.diskNumber -eq [int]$d.diskNumber) { throw 'Duplicate disk number' }
            if ((& $guid $peer.diskGuid) -eq $mDisk -or
                (@($peer.labels) -contains 'TX_TRANSFER')) {
                throw 'Ambiguous/cloned USB disk or duplicate transfer label'
            }
            foreach ($id in @($peer.partitionGuids)) {
                if ($seenGuid.ContainsKey((& $guid $id))) {
                    throw 'Partition unique GUID reused on another USB disk'
                }
            }
        }
        return [ordered]@{ deviceLayoutVerified = $true; result = 'VERIFIED'; reasons = @() }
    } catch {
        $failure.Add($_.Exception.Message)
        return [ordered]@{ deviceLayoutVerified = $false; result = 'FAIL'; reasons = @($failure.ToArray()) }
    }
}
$script:Crc32Table = $null
function Get-Crc32 {
    param([byte[]]$Bytes, [int]$Offset, [int]$Count)
    if ($null -eq $script:Crc32Table) {
        $table = New-Object 'uint32[]' 256
        for ($n = 0; $n -lt 256; $n++) {
            $c = [uint32]$n
            for ($k = 0; $k -lt 8; $k++) {
                if (($c -band 1) -ne 0) { $c = [uint32](3988292384 -bxor ($c -shr 1)) } else { $c = [uint32]($c -shr 1) }
            }
            $table[$n] = $c
        }
        $script:Crc32Table = $table
    }
    $crc = [uint32]4294967295
    for ($i = $Offset; $i -lt $Offset + $Count; $i++) {
        $crc = [uint32]($script:Crc32Table[[int](($crc -bxor $Bytes[$i]) -band 255)] -bxor ($crc -shr 8))
    }
    return [uint32]($crc -bxor 4294967295)
}
function Set-UInt64At([byte[]]$Bytes, [int]$Offset, [uint64]$Value) {
    [Array]::Copy([BitConverter]::GetBytes($Value), 0, $Bytes, $Offset, 8)
}
function Read-SectorsAt([System.IO.Stream]$Stream, [long]$Offset, [int]$Count) {
    [void]$Stream.Seek($Offset, [System.IO.SeekOrigin]::Begin)
    $buffer = New-Object byte[] $Count
    $read = 0
    while ($read -lt $Count) {
        $n = $Stream.Read($buffer, $read, $Count - $read)
        if ($n -le 0) { throw 'Truncated read-only media region' }
        $read += $n
    }
    return ,$buffer
}
function Test-MediaRegionOffset([long]$TransferOffsetBytes) {
    if ($TransferOffsetBytes -le 1024 -or $TransferOffsetBytes -gt 1073741824 -or
        ($TransferOffsetBytes % 512) -ne 0) {
        throw 'Unsafe media readback region'
    }
}
function Get-HashOfRegion([System.IO.Stream]$Stream, [byte[]]$Head, [long]$TransferOffsetBytes) {
    # $Head replaces LBA 0..1 when supplied; the rest is read from the stream.
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $buffer = New-Object byte[] 1048576
    try {
        if ($null -ne $Head) {
            [void]$sha.TransformBlock($Head, 0, 1024, $Head, 0)
            [void]$Stream.Seek(1024, [System.IO.SeekOrigin]::Begin)
            $remaining = $TransferOffsetBytes - 1024
        } else {
            [void]$Stream.Seek(0, [System.IO.SeekOrigin]::Begin)
            $remaining = $TransferOffsetBytes
        }
        while ($remaining -gt 0) {
            $count = [int][Math]::Min($remaining, $buffer.Length)
            $n = $Stream.Read($buffer, 0, $count)
            if ($n -le 0) { throw 'Truncated read-only media region' }
            [void]$sha.TransformBlock($buffer, 0, $n, $buffer, 0)
            $remaining -= $n
        }
        [void]$sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
        return [BitConverter]::ToString($sha.Hash).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}
function Get-MediaRegionSha256 {
    <#
    SHA-256 of LBA 0 up to the start of TX_TRANSFER (protective MBR, primary GPT
    header, GPT entries, ESP, COLD_VAULT) read from an already opened read-only
    stream. TX_TRANSFER is excluded because Windows rewrites its FAT metadata
    when it mounts the volume.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][System.IO.Stream]$Stream,
        [Parameter(Mandatory=$true)][long]$TransferOffsetBytes
    )
    Test-MediaRegionOffset $TransferOffsetBytes
    return Get-HashOfRegion $Stream $null $TransferOffsetBytes
}
function Get-ExpectedMediaRegionSha256 {
    <#
    Expected SHA-256 of the same region on a device flashed with the output of
    scripts/prepare_usb_capacity_image.py for a device of DeviceSizeBytes.
    That tool keeps every byte except the protective MBR size field (offset 458)
    and the primary GPT header geometry (backup LBA, last usable LBA, CRC), so
    the same relocation is applied in memory to the raw image's LBA 0..1.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][System.IO.Stream]$ImageStream,
        [Parameter(Mandatory=$true)][long]$DeviceSizeBytes,
        [Parameter(Mandatory=$true)][long]$TransferOffsetBytes
    )
    Test-MediaRegionOffset $TransferOffsetBytes
    $head = Read-SectorsAt $ImageStream 0 1024
    $ascii = [System.Text.Encoding]::ASCII
    if ($ascii.GetString($head, 512, 8) -ne 'EFI PART' -or
        [BitConverter]::ToUInt32($head, 524) -ne 92 -or
        [BitConverter]::ToUInt64($head, 536) -ne 1 -or
        [BitConverter]::ToUInt64($head, 584) -ne 2) {
        throw 'Raw image primary GPT header is not the expected layout'
    }
    $tableSectors = [long]([BitConverter]::ToUInt32($head, 592)) * [long]([BitConverter]::ToUInt32($head, 596)) / 512
    if ($tableSectors -ne 32) { throw 'Unexpected GPT partition table size' }
    $imageLength = [long]$ImageStream.Length
    if (($DeviceSizeBytes % 512) -ne 0 -or $DeviceSizeBytes -gt 137438953472 -or
        $DeviceSizeBytes -lt $imageLength + ($tableSectors + 1) * 512) {
        throw 'Device capacity is incompatible with capacity image preparation'
    }
    $newLast = [uint64]($DeviceSizeBytes / 512 - 1)
    $newTable = $newLast - [uint64]$tableSectors
    [Array]::Copy([BitConverter]::GetBytes([uint32][Math]::Min([double]$newLast, 4294967295)), 0, $head, 458, 4)
    Set-UInt64At $head (512 + 24) 1
    Set-UInt64At $head (512 + 32) $newLast
    Set-UInt64At $head (512 + 48) ($newTable - 1)
    Set-UInt64At $head (512 + 72) 2
    [Array]::Clear($head, 512 + 16, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32](Get-Crc32 $head 512 92)), 0, $head, 512 + 16, 4)
    return Get-HashOfRegion $ImageStream $head $TransferOffsetBytes
}
Export-ModuleMember -Function Test-PhysicalInventorySnapshot, Get-MediaRegionSha256, Get-ExpectedMediaRegionSha256
