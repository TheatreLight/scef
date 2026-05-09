param(
    [int]$Scale = 3,
    [string]$Background = "white"
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$SrcDir = Join-Path $Root "src"
$PngDir = Join-Path $Root "png"

New-Item -ItemType Directory -Force -Path $PngDir | Out-Null

$mmdc = Get-Command mmdc -ErrorAction Stop

Get-ChildItem -LiteralPath $SrcDir -Filter "*.mmd" | Sort-Object Name | ForEach-Object {
    $out = Join-Path $PngDir ($_.BaseName + ".png")
    Write-Host "Exporting $($_.Name) -> $(Split-Path -Leaf $out)"
    & $mmdc.Source -i $_.FullName -o $out -b $Background -s $Scale
    if ($LASTEXITCODE -ne 0) {
        throw "mmdc failed for $($_.FullName) with exit code $LASTEXITCODE"
    }
}

# Some flowcharts are split into two LR parts (a/b) and recombined here.
$composeScript = Join-Path $Root "compose_two_row_flow.py"
if (Test-Path $composeScript) {
    Write-Host "Composing two-row flow PNGs from parts a + b"
    & python $composeScript
    if ($LASTEXITCODE -ne 0) {
        throw "compose_two_row_flow.py failed with exit code $LASTEXITCODE"
    }
}
