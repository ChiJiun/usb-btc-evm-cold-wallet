#requires -Version 5.1
<#
Read-only Windows USB inventory and SHA-256 check. Never writes to target media.
Example:
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts/physical_usb_inventory.ps1 -DriveLetter F -ImagePath C:\\test\\usb-cold-wallet.img -ExpectedSha256 <64-hex>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z]:?$')][string]$DriveLetter,
    [string]$ImagePath,
    [string]$ExpectedSha256,
    [string]$ExpectedModel,
    [switch]$Json
)
$ErrorActionPreference = 'Stop'
try {
    $letter = $DriveLetter.Substring(0,1).ToUpperInvariant()
    $partition = @(Get-Partition -DriveLetter $letter -ErrorAction Stop)
    if ($partition.Count -ne 1) { throw "Drive letter does not resolve to exactly one partition" }
    $disk = Get-Disk -Number $partition[0].DiskNumber -ErrorAction Stop
    $allPartitions = @(Get-Partition -DiskNumber $disk.Number | Sort-Object PartitionNumber)
    $volumes = @()
    foreach ($p in $allPartitions) {
        $v = $p | Get-Volume -ErrorAction SilentlyContinue
        $volumes += [ordered]@{
            partitionNumber = $p.PartitionNumber
            driveLetter = if ($p.DriveLetter) { [string]$p.DriveLetter } else { $null }
            offsetBytes = [int64]$p.Offset
            sizeBytes = [int64]$p.Size
            gptType = [string]$p.GptType
            type = [string]$p.Type
            label = if ($v) { [string]$v.FileSystemLabel } else { $null }
            filesystem = if ($v) { [string]$v.FileSystem } else { $null }
        }
    }
    $removable = ($disk.BusType -eq 'USB')
    $modelMatches = (!$ExpectedModel -or $disk.FriendlyName -eq $ExpectedModel)
    $sha = $null
    $hashMatches = $null
    if ($ExpectedSha256 -and $ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'ExpectedSha256 must be 64 hex characters' }
    if ($ImagePath) {
        $resolved = (Resolve-Path -LiteralPath $ImagePath -ErrorAction Stop).ProviderPath
        $file = Get-Item -LiteralPath $resolved
        if ($file.PSIsContainer) { throw 'ImagePath is a directory' }
        $sha = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($ExpectedSha256) { $hashMatches = ($sha -eq $ExpectedSha256.ToLowerInvariant()) }
    }
    $result = [ordered]@{
        schemaVersion = 1
        collectedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
        observedDriveLetter = $letter
        diskNumber = [int]$disk.Number
        model = [string]$disk.FriendlyName
        serialNumber = $null # Do not collect a stable hardware identifier by default.
        busType = [string]$disk.BusType
        sizeBytes = [int64]$disk.Size
        partitionStyle = [string]$disk.PartitionStyle
        isReadOnly = [bool]$disk.IsReadOnly
        isOffline = [bool]$disk.IsOffline
        logicalSectorSize = [int]$disk.LogicalSectorSize
        partitions = $volumes
        isUsbBus = [bool]$removable
        expectedModelMatches = [bool]$modelMatches
        imageSha256 = $sha
        imageMatchesExpected = $hashMatches
        result = if (!$removable -or !$modelMatches -or ($ExpectedSha256 -and !$ImagePath) -or ($hashMatches -eq $false)) { 'FAIL' } else { 'PASS' }
    }
    if ($Json) { $result | ConvertTo-Json -Depth 8 } else { $result | ConvertTo-Json -Depth 8 }
    if ($result.result -eq 'FAIL') { exit 2 }
} catch {
    [ordered]@{schemaVersion=1; result='BLOCKED'; reason=$_.Exception.Message} | ConvertTo-Json -Compress
    exit 3
}
