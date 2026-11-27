#requires -Version 5.1
# PowerShell fixtures exercise only the pure verifier; no real USB is touched.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../scripts/physical_usb_inventory_core.psm1') -Force

$commit = 'a' * 40
$hash = 'b' * 64
$manifest = [pscustomobject]@{
    schemaVersion = 1
    layout = 'single-usb-issue-37'
    sourceCommit = $commit
    imageSha256 = $hash
    imageSizeBytes = 672157696
    diskGuid = 'f1448aa1-28cc-54bf-8fdd-3008514c0ab5'
    model = 'Mock USB'
    partitions = @(
        [pscustomobject]@{partitionNumber=1; partitionGuid='e2bd6d1b-8de5-502d-a897-c53a8e60f46b'; gptType='c12a7328-f81f-11d2-ba4b-00a0c93ec93b'; offsetBytes=1048576; sizeBytes=67108864; filesystem='FAT'; label='USBCOLD_EFI'},
        [pscustomobject]@{partitionNumber=2; partitionGuid='18f1c36f-d5c0-5052-9cd2-03e9c2a48f00'; gptType='0fc63daf-8483-4772-8e79-3d69d8477de4'; offsetBytes=68157440; sizeBytes=67108864; filesystem='FAT'; label='COLD_VAULT'},
        [pscustomobject]@{partitionNumber=3; partitionGuid='42f6f5d4-9310-5ac3-b5d4-1540cbe7d6b4'; gptType='ebd0a0a2-b9e5-4433-87c0-68b6b72699c7'; offsetBytes=135266304; sizeBytes=536870912; filesystem='FAT32'; label='TX_TRANSFER'}
    )
}
function New-Snapshot {
    $diskNum = 8
    $parts = @()
    foreach ($p in $manifest.partitions) {
        $parts += [pscustomobject]@{
            diskNumber=$diskNum; partitionNumber=$p.partitionNumber
            partitionGuid=$p.partitionGuid; gptType=$p.gptType
            offsetBytes=$p.offsetBytes; sizeBytes=$p.sizeBytes
            filesystem=$p.filesystem; label=$p.label
            driveLetter=if ($p.partitionNumber -eq 3) {'F'} else {''}
        }
    }
    return [pscustomobject]@{
        driveLetter='F'
        disk=[pscustomobject]@{
            diskNumber=$diskNum; diskGuid=$manifest.diskGuid
            model='Mock USB'; busType='USB'; partitionStyle='GPT'
            sizeBytes=32000000000; logicalSectorSize=512
        }
        partitions=@($parts)
        peers=@()
    }
}
function Copy-Snapshot($inputSnapshot) {
    return ($inputSnapshot | ConvertTo-Json -Depth 10 | ConvertFrom-Json)
}
$count = 0
function Assert-Inventory([string]$Name, [object]$Snapshot, [bool]$Expected) {
    $actual = Test-PhysicalInventorySnapshot -Snapshot $Snapshot -Manifest $manifest
    if ([bool]$actual.deviceLayoutVerified -ne $Expected) {
        throw "PowerShell fixture $Name failed. result=$($actual | ConvertTo-Json -Compress)"
    }
    $script:count++
}
$baseline = New-Snapshot
Assert-Inventory 'correct three-partition USB' $baseline $true

$wrong = Copy-Snapshot $baseline
$wrong.disk.busType = 'SATA'
Assert-Inventory 'non USB system disk' $wrong $false

$wrong = Copy-Snapshot $baseline
$wrong.disk.diskGuid = '00000000-0000-0000-0000-000000000000'
Assert-Inventory 'wrong parent disk GUID' $wrong $false

$wrong = Copy-Snapshot $baseline
$wrong.partitions[0].diskNumber = 99
Assert-Inventory 'wrong parent of EFI' $wrong $false

$wrong = Copy-Snapshot $baseline
$wrong.partitions[2].diskNumber = 99
Assert-Inventory 'wrong parent of transfer' $wrong $false

$wrong = Copy-Snapshot $baseline
$wrong.partitions[1].partitionGuid = '00000000-0000-0000-0000-000000000000'
Assert-Inventory 'wrong unique GUID' $wrong $false

$wrong = Copy-Snapshot $baseline
$wrong.partitions[1].partitionGuid = $wrong.partitions[0].partitionGuid
Assert-Inventory 'duplicate partition GUIDs' $wrong $false

$wrong = Copy-Snapshot $baseline
$wrong.partitions[1].gptType = $wrong.partitions[2].gptType
Assert-Inventory 'wrong type GUID' $wrong $false

$wrong = Copy-Snapshot $baseline
$wrong.partitions[1].offsetBytes += 512
Assert-Inventory 'wrong partition offset' $wrong $false

$wrong = Copy-Snapshot $baseline
$wrong.partitions[2].sizeBytes -= 512
Assert-Inventory 'wrong partition size' $wrong $false

$wrong = Copy-Snapshot $baseline
$wrong.partitions[2].partitionNumber = 4
Assert-Inventory 'wrong partition number' $wrong $false

$wrong = Copy-Snapshot $baseline
$wrong.partitions[1].label = 'TX_TRANSFER'
Assert-Inventory 'duplicate labels' $wrong $false

$wrong = Copy-Snapshot $baseline
$wrong.partitions[1].filesystem = ''
Assert-Inventory 'hidden vault filesystem unavailable' $wrong $false

$wrong = Copy-Snapshot $baseline
$wrong.partitions[2].driveLetter = 'G'
Assert-Inventory 'wrong transfer letter' $wrong $false

$wrong = Copy-Snapshot $baseline
$wrong.partitions[0].driveLetter = 'E'
Assert-Inventory 'unexpected EFI mount letter' $wrong $false

$wrong = Copy-Snapshot $baseline
$wrong.peers = @([pscustomobject]@{diskNumber=9; diskGuid=$manifest.diskGuid; model='Different';
        labels=@('Other'); partitionGuids=@()})
Assert-Inventory 'cloned disk GUID' $wrong $false

$wrong = Copy-Snapshot $baseline
$wrong.peers = @([pscustomobject]@{diskNumber=9; diskGuid='00000000-0000-0000-0000-000000000001';
        model='Mock USB'; labels=@('TX_TRANSFER'); partitionGuids=@()})
Assert-Inventory 'same-label and model fake USB' $wrong $false
$wrong = Copy-Snapshot $baseline
$wrong.peers = @([pscustomobject]@{diskNumber=9; diskGuid='00000000-0000-0000-0000-000000000001';
        model='Other USB Model'; labels=@('TX_TRANSFER'); partitionGuids=@()})
Assert-Inventory 'same-label fake USB with different model' $wrong $false

$wrong = Copy-Snapshot $baseline
$wrong.peers = @([pscustomobject]@{diskNumber=9; diskGuid='00000000-0000-0000-0000-000000000001';
        model='Different'; labels=@('Other'); partitionGuids=@($manifest.partitions[2].partitionGuid)})
Assert-Inventory 'peer duplicate PARTUUID' $wrong $false

$replug = Copy-Snapshot $baseline
$replug.disk.diskNumber = 14
$replug.driveLetter = 'G'
foreach ($p in $replug.partitions) {
    $p.diskNumber = 14
    if ($p.partitionNumber -eq 3) { $p.driveLetter = 'G' }
}
Assert-Inventory 'fresh legitimate replug renumbering' $replug $true
$replug.disk.diskGuid = '00000000-0000-0000-0000-000000000002'
Assert-Inventory 'replacement disk after replug' $replug $false

$manifestBad = Copy-Snapshot $manifest
$manifestBad.imageSha256 = 'invalid'
if ((Test-PhysicalInventorySnapshot -Snapshot $baseline -Manifest $manifestBad).deviceLayoutVerified) {
    throw 'Invalid trusted hash should fail closed'
}
$count++

# Media readback region: [LBA 0, TX_TRANSFER). The expected hash re-applies the
# capacity relocation (MBR size + primary GPT header) to the raw image in memory.
# Byte-exact equality with scripts/prepare_usb_capacity_image.py output is
# covered by tests/test_physical_acceptance.py (TestCapacityImageReadback).
$txOffset = 8192
$deviceSize = 65536
function New-RawImage {
    $b = New-Object byte[] 12288
    for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [byte]($i % 251) }
    [Array]::Copy([System.Text.Encoding]::ASCII.GetBytes('EFI PART'), 0, $b, 512, 8)
    [Array]::Copy([BitConverter]::GetBytes([uint32]92), 0, $b, 524, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint64]1), 0, $b, 536, 8)
    [Array]::Copy([BitConverter]::GetBytes([uint64]2), 0, $b, 584, 8)
    [Array]::Copy([BitConverter]::GetBytes([uint32]128), 0, $b, 592, 4)
    [Array]::Copy([BitConverter]::GetBytes([uint32]128), 0, $b, 596, 4)
    return ,$b
}
function Get-Expected([byte[]]$Bytes, [long]$Size = $deviceSize, [long]$Offset = $txOffset) {
    $s = New-Object System.IO.MemoryStream (,$Bytes)
    try { return Get-ExpectedMediaRegionSha256 -ImageStream $s -DeviceSizeBytes $Size -TransferOffsetBytes $Offset } finally { $s.Dispose() }
}
function Get-Media([byte[]]$Bytes, [long]$Offset = $txOffset) {
    $s = New-Object System.IO.MemoryStream (,$Bytes)
    try { return Get-MediaRegionSha256 -Stream $s -TransferOffsetBytes $Offset } finally { $s.Dispose() }
}
function Assert-Throws([string]$Name, [scriptblock]$Block) {
    $threw = $false
    try { [void](& $Block) } catch { $threw = $true }
    if (-not $threw) { throw "Readback fixture $Name must fail closed" }
    $script:count++
}
function Assert-True([string]$Name, [bool]$Condition) {
    if (-not $Condition) { throw "Readback fixture $Name failed" }
    $script:count++
}
$raw = New-RawImage
$expected = Get-Expected $raw
Assert-True 'expected hash is deterministic' ($expected -eq (Get-Expected (New-RawImage)))
Assert-True 'expected hash relocates MBR/GPT header' ($expected -ne (Get-Media $raw))
Assert-True 'expected hash depends on device capacity' ($expected -ne (Get-Expected $raw ($deviceSize + 512)))
$changed = New-RawImage; $changed[$txOffset + 3] = [byte]($changed[$txOffset + 3] -bxor 0xFF)
Assert-True 'TX_TRANSFER bytes excluded (expected)' ($expected -eq (Get-Expected $changed))
$changed = New-RawImage; $changed[$txOffset - 1] = [byte]($changed[$txOffset - 1] -bxor 0xFF)
Assert-True 'ESP/vault byte changes expected hash' ($expected -ne (Get-Expected $changed))
$changed = New-RawImage; $changed[1024] = [byte]($changed[1024] -bxor 0xFF)
Assert-True 'GPT entry array (LBA 2) changes expected hash' ($expected -ne (Get-Expected $changed))
$changed = New-RawImage; $changed[10] = [byte]($changed[10] -bxor 0xFF)
Assert-True 'protective MBR boot code changes expected hash' ($expected -ne (Get-Expected $changed))
$media = New-RawImage; $tx = New-RawImage; $tx[$txOffset + 3] = 0
Assert-True 'TX_TRANSFER bytes excluded (media)' ((Get-Media $media) -eq (Get-Media $tx))
$changed = New-RawImage; $changed[600] = [byte]($changed[600] -bxor 0xFF)
Assert-True 'media primary GPT header compared byte-exactly' ((Get-Media $media) -ne (Get-Media $changed))

foreach ($case in @(@{o=512; v=0x41}, @{o=524; v=93}, @{o=536; v=2}, @{o=584; v=3}, @{o=592; v=64})) {
    $bad = New-RawImage
    $bad[$case.o] = [byte]$case.v
    Assert-Throws "bad raw GPT header offset $($case.o)" { Get-Expected $bad }
}
foreach ($size in @(12288, (12288 + 33 * 512 - 512), ($deviceSize + 1), (137438953472 + 512))) {
    Assert-Throws "incompatible device capacity $size" { Get-Expected $raw $size }
}
foreach ($bad in @(0, 1024, 1000, 1073741825)) {
    Assert-Throws "unsafe media offset $bad" { Get-Media $raw $bad }
    Assert-Throws "unsafe expected offset $bad" { Get-Expected $raw $deviceSize $bad }
}
Assert-Throws 'truncated media' { Get-Media (New-Object byte[] 4096) }
Assert-Throws 'truncated raw image' { Get-Expected ((New-RawImage)[0..4095]) }
Write-Output "PowerShell mocked physical inventory fixtures: $count PASS (hardware NOT TESTED)"
