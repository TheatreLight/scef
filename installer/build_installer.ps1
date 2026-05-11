#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the SCEF Windows MSI installer using WiX 3.

.DESCRIPTION
    1. Verifies prerequisites (WiX 3 candle/light/heat, CMake, Qt, Python3)
    2. Builds SCEF Release with -DSCEF_BUILD_GUI=ON
    3. Populates installer/staging/ (binaries + Qt runtime via windeployqt)
    4. Downloads VC_redist.x64.exe to installer/cache/ if absent
    5. Generates THIRD_PARTY_LICENSES.txt
    6. Generates a minimal placeholder scef.ico if absent
    7. Runs heat + candle + light to produce dist/scef-<version>-x64.msi

    This script intentionally uses WiX 3.14 (candle/light/heat) rather than
    the WiX 5 dotnet global tool, so no .NET SDK installation is required.

.PARAMETER QtDir
    Override Qt installation root, e.g. C:\Qt\6.11.0\msvc2022_64
    If omitted, the script checks $env:QT_DIR then tries C:\Qt\6.11.0\msvc2022_64.

.PARAMETER SkipBuild
    Skip the CMake build step (use existing artifacts in build/release-installer/).

.PARAMETER SkipDeploy
    Skip windeployqt step (use existing staging/ contents).

.EXAMPLE
    # Standard build from repo root:
    cd C:\pet_p\MEPHI_DIPLOMA
    .\scef\installer\build_installer.ps1

.EXAMPLE
    # With explicit Qt path:
    .\scef\installer\build_installer.ps1 -QtDir "C:\Qt\6.11.0\msvc2022_64"
#>

[CmdletBinding()]
param(
    [string]$QtDir      = "",
    [switch]$SkipBuild  = $false,
    [switch]$SkipDeploy = $false
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ─── Paths ────────────────────────────────────────────────────────────────────

# Script is at scef/installer/ — derive repo root from that
$ScriptDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScefDir      = Split-Path -Parent $ScriptDir        # scef/
$RepoRoot     = Split-Path -Parent $ScefDir           # repo root

$BuildDir     = Join-Path $ScefDir "build\release-installer"
$StagingDir   = Join-Path $ScriptDir "staging"
$CacheDir     = Join-Path $ScriptDir "cache"
$DistDir      = Join-Path $ScriptDir "dist"
$AssetsDir    = Join-Path $ScriptDir "assets"
$VcpkgBinDir  = Join-Path $RepoRoot "vcpkg\installed\x64-windows\bin"
$QmlDir       = Join-Path $ScefDir "gui\qml"

$VcRedistUrl  = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
$VcRedistPath = Join-Path $CacheDir "VC_redist.x64.exe"

# ─── Utility ──────────────────────────────────────────────────────────────────

function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}

function Fail([string]$msg) {
    Write-Host ""
    Write-Host "ERROR: $msg" -ForegroundColor Red
    exit 1
}

function Require-Command([string]$name, [string]$hint) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Fail "$name not found on PATH. $hint"
    }
}

# ─── Step 0: Verify prerequisites ─────────────────────────────────────────────

Write-Step "Verifying prerequisites"

# cmake
Require-Command "cmake" "Install CMake from https://cmake.org/download/ and add to PATH."

# ninja
Require-Command "ninja" "Install Ninja: choco install ninja  OR  add CMake's bundled ninja to PATH."

# python3
Require-Command "python" "Install Python 3 from https://python.org and add to PATH."

# Locate WiX 3 toolset.
# The official WiX 3 installer sets the WIX environment variable to its root dir.
# Fall back to the well-known default installation path.
$Wix3Bin = ""
$wixEnv = [System.Environment]::GetEnvironmentVariable("WIX", "Machine")
if (-not $wixEnv) {
    $wixEnv = [System.Environment]::GetEnvironmentVariable("WIX", "User")
}
if ($wixEnv -and (Test-Path (Join-Path $wixEnv "bin\candle.exe"))) {
    $Wix3Bin = Join-Path $wixEnv "bin"
} elseif (Test-Path "C:\Program Files (x86)\WiX Toolset v3.14\bin\candle.exe") {
    $Wix3Bin = "C:\Program Files (x86)\WiX Toolset v3.14\bin"
} else {
    Fail ("WiX 3 candle.exe not found.`n" +
          "Install WiX 3.14 from https://github.com/wixtoolset/wix3/releases/tag/wix3141rtm`n" +
          "The official installer sets the WIX environment variable automatically.")
}

$CandleExe = Join-Path $Wix3Bin "candle.exe"
$LightExe  = Join-Path $Wix3Bin "light.exe"
$HeatExe   = Join-Path $Wix3Bin "heat.exe"

foreach ($tool in @($CandleExe, $LightExe, $HeatExe)) {
    if (-not (Test-Path $tool)) {
        Fail "WiX 3 tool not found: $tool"
    }
}

Write-Host "WiX 3 bin: $Wix3Bin"
Write-Host "candle: $CandleExe"
Write-Host "light:  $LightExe"
Write-Host "heat:   $HeatExe"

# Qt windeployqt
$QtBinDir = ""
if (-not [string]::IsNullOrEmpty($QtDir)) {
    $QtBinDir = Join-Path $QtDir "bin"
} elseif (-not [string]::IsNullOrEmpty($env:QT_DIR)) {
    $QtBinDir = Join-Path $env:QT_DIR "bin"
} else {
    # Auto-detect: try common locations
    $candidates = @(
        "C:\Qt\6.11.0\msvc2022_64\bin",
        "C:\Qt\6.10.0\msvc2022_64\bin",
        "C:\Qt\6.9.0\msvc2022_64\bin"
    )
    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c "windeployqt.exe")) {
            $QtBinDir = $c
            break
        }
    }
    if ($QtBinDir -eq "") {
        Fail "windeployqt.exe not found. Set QT_DIR env var or pass -QtDir to this script."
    }
}

$WinDeployQt = Join-Path $QtBinDir "windeployqt.exe"
if (-not (Test-Path $WinDeployQt)) {
    Fail "windeployqt.exe not found at: $WinDeployQt"
}
Write-Host "Qt bin: $QtBinDir"
Write-Host "windeployqt: $WinDeployQt"

# botan-3.dll
if (-not (Test-Path (Join-Path $VcpkgBinDir "botan-3.dll"))) {
    Fail "botan-3.dll not found at $VcpkgBinDir. Run: vcpkg install botan:x64-windows"
}

# ─── Step 1: Read version from CMakeLists.txt ─────────────────────────────────

Write-Step "Reading project version"

$CmakeListsPath = Join-Path $ScefDir "CMakeLists.txt"
$cmakeContent = Get-Content $CmakeListsPath -Raw
if ($cmakeContent -match 'project\s*\([^)]*VERSION\s+(\d+\.\d+\.\d+)') {
    $Version = $Matches[1]
} else {
    Fail "Could not parse VERSION from $CmakeListsPath"
}
Write-Host "Version: $Version"

# ─── Step 2: CMake Release build ──────────────────────────────────────────────

if (-not $SkipBuild) {
    Write-Step "Configuring CMake Release build (SCEF_BUILD_GUI=ON)"

    $ToolchainFile = Join-Path $RepoRoot "vcpkg\scripts\buildsystems\vcpkg.cmake"

    $cmakeArgs = @(
        "-B", $BuildDir,
        "-S", $ScefDir,
        "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=Release",
        "-DSCEF_BUILD_GUI=ON",
        "-DSCEF_BUILD_TESTS=OFF",
        "-DCMAKE_TOOLCHAIN_FILE=$ToolchainFile",
        "-DCMAKE_PREFIX_PATH=$(Split-Path $QtBinDir -Parent)"
    )

    & cmake @cmakeArgs
    if ($LASTEXITCODE -ne 0) { Fail "cmake configure failed." }

    Write-Step "Building (cmake --build)"
    & cmake --build $BuildDir
    if ($LASTEXITCODE -ne 0) { Fail "cmake build failed." }
} else {
    Write-Host "Skipping CMake build (--SkipBuild)" -ForegroundColor Yellow
}

# ─── Step 3: Populate staging/ ────────────────────────────────────────────────

Write-Step "Populating staging directory"

# Clean and recreate staging
if (Test-Path $StagingDir) {
    Remove-Item $StagingDir -Recurse -Force
}
New-Item -ItemType Directory -Path $StagingDir | Out-Null

# Binaries from the build tree
$GuiBuildDir = Join-Path $BuildDir "gui"
$StagingGuiExe = Join-Path $StagingDir "scef-gui.exe"
$StagingCliExe = Join-Path $StagingDir "scef.exe"

$CliExe = Join-Path $BuildDir "scef.exe"
$GuiExe = Join-Path $GuiBuildDir "scef-gui.exe"

if (-not (Test-Path $CliExe)) { Fail "scef.exe not found at $CliExe. Did the build succeed?" }
if (-not (Test-Path $GuiExe)) { Fail "scef-gui.exe not found at $GuiExe. Did the GUI build succeed?" }

Copy-Item $CliExe $StagingDir
Copy-Item $GuiExe $StagingDir
Write-Host "Copied scef.exe and scef-gui.exe"

# index.html (browser viewer)
$IndexHtml = Join-Path $BuildDir "index.html"
if (Test-Path $IndexHtml) {
    Copy-Item $IndexHtml $StagingDir
    Write-Host "Copied index.html"
} else {
    # Try the GUI build subdirectory
    $IndexHtmlGui = Join-Path $GuiBuildDir "index.html"
    if (Test-Path $IndexHtmlGui) {
        Copy-Item $IndexHtmlGui $StagingDir
        Write-Host "Copied index.html (from GUI build dir)"
    } else {
        Write-Host "WARNING: index.html not found — browser viewer will not be included." -ForegroundColor Yellow
    }
}

# botan-3.dll
Copy-Item (Join-Path $VcpkgBinDir "botan-3.dll") $StagingDir
Write-Host "Copied botan-3.dll"

# Qt runtime: windeployqt populates DLLs and QML modules next to scef-gui.exe
if (-not $SkipDeploy) {
    Write-Step "Running windeployqt"
    # NOTE: do NOT pass --no-opengl-sw. opengl32sw.dll is Qt's Mesa software
    # rasterizer fallback, required on machines with no hardware OpenGL driver
    # (RDP sessions, GPU-less VMs, some hypervisors). Excluding it leaves the
    # GUI with a black/blank window on those targets. The size cost (~15 MB)
    # is acceptable.
    & $WinDeployQt `
        --release `
        --qmldir $QmlDir `
        --no-translations `
        --no-system-d3d-compiler `
        $StagingGuiExe
    if ($LASTEXITCODE -ne 0) { Fail "windeployqt failed." }
    Write-Host "windeployqt complete"
} else {
    Write-Host "Skipping windeployqt (--SkipDeploy)" -ForegroundColor Yellow
}

# qt_add_qml_module produces an app-defined QML module under <build>/gui/<URI>/
# containing qmldir + .qml files. windeployqt only deploys Qt's own QML modules,
# not application modules, so we copy it ourselves. Without this, the QML engine
# fails with: 'Module "scef" contains no type named "Main"'.
$AppQmlModuleSrc = Join-Path $GuiBuildDir "scef"
$AppQmlModuleDst = Join-Path $StagingDir "scef"
if (Test-Path (Join-Path $AppQmlModuleSrc "qmldir")) {
    Write-Step "Copying application QML module (scef/)"
    Copy-Item -Path $AppQmlModuleSrc -Destination $AppQmlModuleDst -Recurse -Force
    Write-Host "Copied: $AppQmlModuleSrc -> $AppQmlModuleDst"
} else {
    Fail "Application QML module not found at $AppQmlModuleSrc. Did the GUI build complete?"
}

# Copy placeholder icon into staging so WiX harvest finds nothing extra;
# the icon component in Package.wxs reads from assets\ directly.
# (No action needed here — WiX reads assets\scef.ico via its Source attribute.)

# ─── Step 4: Download VC_redist ───────────────────────────────────────────────

Write-Step "Checking VC++ 2022 Redistributable"

New-Item -ItemType Directory -Force -Path $CacheDir | Out-Null

if (Test-Path $VcRedistPath) {
    Write-Host "VC_redist.x64.exe already cached at $VcRedistPath"
} else {
    Write-Host "Downloading from $VcRedistUrl ..."
    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($VcRedistUrl, $VcRedistPath)
        Write-Host "Downloaded to $VcRedistPath"
    } catch {
        Fail "Failed to download VC_redist.x64.exe: $_`nDownload manually from $VcRedistUrl and save to $VcRedistPath"
    }
}

# ─── Step 5: Generate THIRD_PARTY_LICENSES.txt ────────────────────────────────

Write-Step "Generating THIRD_PARTY_LICENSES.txt"

$LicenseOut = Join-Path $StagingDir "THIRD_PARTY_LICENSES.txt"

$botanlLicenseFile = Join-Path $RepoRoot "vcpkg\installed\x64-windows\share\botan\copyright"
$botanLicenseText  = if (Test-Path $botanlLicenseFile) { Get-Content $botanlLicenseFile -Raw } else {
    "Botan 3.x - BSD 2-Clause License`nhttps://botan.randombit.net/`nSee https://github.com/randombit/botan/blob/master/license.txt`n"
}

$content = @"
SCEF Third-Party Licenses
==========================
This file lists open-source components bundled with SCEF.

--------------------------------------------------------------------------------
Botan 3.x
https://botan.randombit.net/
--------------------------------------------------------------------------------
$botanLicenseText

--------------------------------------------------------------------------------
Qt 6
https://www.qt.io/
--------------------------------------------------------------------------------
Qt is distributed under the GNU Lesser General Public License version 3 (LGPL v3).
LGPL v3: https://www.gnu.org/licenses/lgpl-3.0.html

In accordance with the LGPL, this application links Qt dynamically.
Qt source code is available at https://code.qt.io/.

--------------------------------------------------------------------------------
nlohmann/json
https://github.com/nlohmann/json
--------------------------------------------------------------------------------
MIT License
Copyright (c) 2013-2024 Niels Lohmann

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished
to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

--------------------------------------------------------------------------------
zxcvbn-c (password strength estimator)
https://github.com/tsyrogit/zxcvbn-c
--------------------------------------------------------------------------------
MIT License -- see above MIT terms applied to zxcvbn-c.
Original JavaScript version by Dan Wheeler (Dropbox).
C port by Chad Thatcher.

--------------------------------------------------------------------------------
Visual C++ 2022 Redistributable
--------------------------------------------------------------------------------
Copyright (c) Microsoft Corporation. All rights reserved.
Distributed under Microsoft Software License Terms.
https://visualstudio.microsoft.com/legal/mslt/

"@

Set-Content -Path $LicenseOut -Value $content -Encoding UTF8
Write-Host "Written: $LicenseOut"

# ─── Step 6: Verify icon asset ────────────────────────────────────────────────

Write-Step "Verifying icon asset"

$IconPath = Join-Path $AssetsDir "scef.ico"
if (-not (Test-Path $IconPath)) {
    Fail "Icon not found: $IconPath. It should be checked into git under installer/assets/."
}
Write-Host "Icon present: $IconPath"

# ─── Step 7: Invoke WiX 3 build pipeline ──────────────────────────────────────

Write-Step "Building MSI with WiX 3 (heat -> candle -> light)"

New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

$MsiName = "scef-$Version-x64.msi"
$MsiPath = Join-Path $DistDir $MsiName

# Resolve staging to an absolute path — WiX requires absolute paths.
$AbsStagingDir = (Resolve-Path $StagingDir).Path

Push-Location $ScriptDir
try {

    # --- 7a: heat — harvest all files from staging into Harvest.wxs ----------
    #
    # Flags:
    #   -cg HarvestedFiles   component group Id (referenced in Package.wxs)
    #   -gg                  generate GUIDs for components
    #   -g1                  use a single GUID per component (not per-file)
    #   -srd                 suppress root directory element (INSTALLFOLDER provided by Package.wxs)
    #   -sreg                suppress registry harvesting
    #   -sfrag               suppress Fragment wrapper (inline into Product)
    #   -dr INSTALLFOLDER    set default install directory reference
    #   -var var.StagingDir  use preprocessor variable so candle can resolve file paths
    Write-Host ""
    Write-Host "Running heat..." -ForegroundColor DarkCyan
    $heatArgs = @(
        "dir", $AbsStagingDir,
        "-cg", "HarvestedFiles",
        "-gg",
        "-g1",
        "-srd",
        "-sreg",
        "-sfrag",
        "-dr", "INSTALLFOLDER",
        "-var", "var.StagingDir",
        "-out", "Harvest.wxs"
    )
    Write-Host "  $HeatExe $($heatArgs -join ' ')"
    & $HeatExe @heatArgs
    if ($LASTEXITCODE -ne 0) { Fail "heat failed (exit $LASTEXITCODE)." }

    # --- 7b: candle — compile Package.wxs and Harvest.wxs into .wixobj ------
    Write-Host ""
    Write-Host "Running candle..." -ForegroundColor DarkCyan
    $candleArgs = @(
        "-arch", "x64",
        "-dVersion=$Version",
        "-dStagingDir=$AbsStagingDir",
        "-ext", (Join-Path $Wix3Bin "WixUIExtension.dll"),
        "-ext", (Join-Path $Wix3Bin "WixUtilExtension.dll"),
        "Package.wxs",
        "Harvest.wxs"
    )
    Write-Host "  $CandleExe $($candleArgs -join ' ')"
    & $CandleExe @candleArgs
    if ($LASTEXITCODE -ne 0) { Fail "candle failed (exit $LASTEXITCODE)." }

    # --- 7c: light — link into MSI ------------------------------------------
    Write-Host ""
    Write-Host "Running light..." -ForegroundColor DarkCyan
    $lightArgs = @(
        "-ext", (Join-Path $Wix3Bin "WixUIExtension.dll"),
        "-ext", (Join-Path $Wix3Bin "WixUtilExtension.dll"),
        "-cultures:en-us",
        "-out", $MsiPath,
        "Package.wixobj",
        "Harvest.wixobj"
    )
    Write-Host "  $LightExe $($lightArgs -join ' ')"
    & $LightExe @lightArgs
    if ($LASTEXITCODE -ne 0) { Fail "light failed (exit $LASTEXITCODE)." }

} finally {
    Pop-Location
}

# ─── Step 8: Clean intermediate files ─────────────────────────────────────────

Write-Step "Cleaning intermediate build artifacts"

$intermediates = @(
    (Join-Path $ScriptDir "Package.wixobj"),
    (Join-Path $ScriptDir "Harvest.wixobj"),
    (Join-Path $ScriptDir "Harvest.wxs"),
    (Join-Path $ScriptDir "Package.wixpdb"),
    (Join-Path $ScriptDir "Harvest.wixpdb")
)
foreach ($f in $intermediates) {
    if (Test-Path $f) {
        Remove-Item $f -Force
        Write-Host "Deleted: $f"
    }
}

# ─── Step 9: Report ───────────────────────────────────────────────────────────

Write-Host ""
Write-Host "======================================" -ForegroundColor Green
Write-Host "MSI build complete!" -ForegroundColor Green
$size = (Get-Item $MsiPath).Length
$sizeMb = [math]::Round($size / 1MB, 1)
Write-Host "Output : $MsiPath" -ForegroundColor Green
Write-Host "Size   : $sizeMb MB ($size bytes)" -ForegroundColor Green
Write-Host "======================================" -ForegroundColor Green
