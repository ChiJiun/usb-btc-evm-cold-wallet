param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Tag,
    [Parameter(Mandatory = $true, Position = 1)]
    [string]$SourceSha,
    [Parameter(Mandatory = $true, Position = 2)]
    [string]$WorkflowSha,
    [Parameter(Mandatory = $true, Position = 3)]
    [string]$Asset
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Verifier = Join-Path $Root "scripts\verify_release_assets.py"

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "gh is required"
}

$Python = Get-Command python3 -ErrorAction SilentlyContinue
if (-not $Python) {
    $Python = Get-Command python -ErrorAction SilentlyContinue
}
if (-not $Python) {
    throw "python3/python is required"
}

$Args = @(
    $Verifier,
    "--tag", $Tag,
    "--commit", $SourceSha,
    "--workflow-sha", $WorkflowSha,
    "--asset", $Asset
)
& $Python.Source @Args
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
