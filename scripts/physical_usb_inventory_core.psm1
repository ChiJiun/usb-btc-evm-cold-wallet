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
            if ([string]$p.label -cne [string]$e.label -or
                [string]$p.filesystem -ne [string]$e.filesystem) {
                throw "Partition $($i+1) FAT label/filesystem mismatch or unavailable"
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
function Get-StableMediaRegionSha256 {
    <#
    Hash only the media regions that must stay byte-identical to the raw image
    after flashing: the protective MBR (LBA 0) and everything from LBA 2 up to
    the start of TX_TRANSFER (GPT entries, ESP, COLD_VAULT).
    LBA 1 is excluded because scripts/prepare_usb_capacity_image.py rewrites the
    primary GPT header (backup LBA, last usable LBA, CRC) for the device capacity.
    TX_TRANSFER is excluded because Windows rewrites FAT metadata when mounting it.
    The caller supplies an already opened read-only stream; no path is opened here.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][System.IO.Stream]$Stream,
        [Parameter(Mandatory=$true)][long]$TransferOffsetBytes
    )
    if ($TransferOffsetBytes -le 1024 -or $TransferOffsetBytes -gt 1073741824 -or
        ($TransferOffsetBytes % 512) -ne 0) {
        throw 'Unsafe stable readback region'
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $buffer = New-Object byte[] 1048576
    try {
        foreach ($range in @(@(0, 512), @(1024, $TransferOffsetBytes))) {
            [void]$Stream.Seek([long]$range[0], [System.IO.SeekOrigin]::Begin)
            $remaining = [long]$range[1] - [long]$range[0]
            while ($remaining -gt 0) {
                $count = [int][Math]::Min($remaining, $buffer.Length)
                $n = $Stream.Read($buffer, 0, $count)
                if ($n -le 0) { throw 'Truncated read-only stable media region' }
                [void]$sha.TransformBlock($buffer, 0, $n, $buffer, 0)
                $remaining -= $n
            }
        }
        [void]$sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
        return [BitConverter]::ToString($sha.Hash).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}
Export-ModuleMember -Function Test-PhysicalInventorySnapshot, Get-StableMediaRegionSha256
