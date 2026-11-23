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
    imageSizeBytes = 671088640
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
Write-Output "PowerShell mocked physical inventory fixtures: $count PASS (hardware NOT TESTED)"
