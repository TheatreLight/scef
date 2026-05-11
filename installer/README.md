# SCEF Windows Installer

Builds `scef-<version>-x64.msi` — a single per-machine MSI installer for SCEF.

This installer intentionally uses **WiX 3** (not WiX 5) so it builds with the
already-installed WiX Toolset v3.14 without requiring the .NET SDK or the
`dotnet tool install wix` global tool.

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| WiX 3.14 | 3.14 | https://github.com/wixtoolset/wix3/releases/tag/wix3141rtm |
| CMake | 3.21+ | https://cmake.org/download/ |
| Ninja | any | `choco install ninja` or bundled with Visual Studio |
| Python 3 | 3.8+ | https://python.org (for browser viewer build) |
| Qt 6.11.0 msvc2022_64 | 6.11.0 | https://www.qt.io/download — set `QT_DIR` env var |

> **WiX 3 install note:** The official WiX 3.14 MSI installer at the link above
> places `candle.exe`, `light.exe`, and `heat.exe` under
> `C:\Program Files (x86)\WiX Toolset v3.14\bin\` and sets the `WIX` environment
> variable to that root directory. The build script detects both automatically.

## Quick Start

Run from the repository root (`C:\pet_p\MEPHI_DIPLOMA`):

```powershell
# Build the MSI:
.\scef\installer\build_installer.ps1
```

The script auto-detects Qt at `C:\Qt\6.11.0\msvc2022_64`. Override with:

```powershell
.\scef\installer\build_installer.ps1 -QtDir "C:\Qt\6.11.0\msvc2022_64"
```

Output: `scef\installer\dist\scef-0.1.0-x64.msi`

## What the Script Does

1. Verifies prereqs (WiX 3 candle/light/heat, cmake, ninja, python, windeployqt)
2. Reads `PROJECT_VERSION` from `scef/CMakeLists.txt`
3. CMake Release build to `scef/build/release-installer/` with `-DSCEF_BUILD_GUI=ON`
4. Populates `installer/staging/`:
   - `scef.exe`, `scef-gui.exe` from the build tree
   - `index.html` from `build/release-installer/` (browser viewer)
   - `botan-3.dll` from `vcpkg/installed/x64-windows/bin/`
   - All Qt 6 runtime DLLs + QML modules via `windeployqt --release --qmldir gui/qml`
   - `THIRD_PARTY_LICENSES.txt` (generated)
5. Downloads `VC_redist.x64.exe` to `installer/cache/` from `https://aka.ms/vs/17/release/vc_redist.x64.exe`
6. Verifies that `assets/scef.ico` exists (it is checked into git)
7. Runs `heat` to harvest staging files into `Harvest.wxs`
8. Runs `candle` to compile `Package.wxs` + `Harvest.wxs` into `.wixobj` files
9. Runs `light` to link everything into `dist/scef-X.Y.Z-x64.msi`
10. Deletes intermediate `Harvest.wxs`, `*.wixobj`, `*.wixpdb`

## Manual Build Commands

If you prefer to run WiX 3 directly (after populating `staging/` yourself).
Use full paths to the WiX 3 binaries since they are not on `PATH` by default.

```powershell
$wix = "C:\Program Files (x86)\WiX Toolset v3.14\bin"
$staging = (Resolve-Path .\staging).Path   # must be absolute

cd scef\installer

# 1. Harvest staged files
& "$wix\heat.exe" dir $staging `
    -cg HarvestedFiles -gg -g1 -srd -sreg -sfrag `
    -dr INSTALLFOLDER -var var.StagingDir -out Harvest.wxs

# 2. Compile
& "$wix\candle.exe" -arch x64 `
    -dVersion=0.1.0 `
    -dStagingDir=$staging `
    -ext "$wix\WixUIExtension.dll" `
    -ext "$wix\WixUtilExtension.dll" `
    Package.wxs Harvest.wxs

# 3. Link
& "$wix\light.exe" `
    -ext "$wix\WixUIExtension.dll" `
    -ext "$wix\WixUtilExtension.dll" `
    -cultures:en-us `
    -out dist\scef-0.1.0-x64.msi `
    Package.wixobj Harvest.wixobj
```

## Script Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-QtDir` | auto-detect | Qt msvc2022_64 root, e.g. `C:\Qt\6.11.0\msvc2022_64` |
| `-SkipBuild` | false | Skip CMake build, use existing artifacts |
| `-SkipDeploy` | false | Skip windeployqt, use existing staging/ contents |

## What Gets Installed

| File | Description |
|------|-------------|
| `scef.exe` | CLI tool |
| `scef-gui.exe` | Qt 6 QML GUI |
| `index.html` | Browser-based viewer (open locally in Chrome/Firefox) |
| `botan-3.dll` | Botan cryptography library |
| Qt6 DLLs + QML | Runtime required by the GUI |
| `scef.ico` | Icon for .scef file association |
| `THIRD_PARTY_LICENSES.txt` | License notices for all bundled OSS components |

## Installer Features

**Install directory:** `C:\Program Files\SCEF\`

**Start Menu:** `SCEF\SCEF` shortcut to `scef-gui.exe` (always installed)

**Desktop shortcut:** Optional, off by default — enabled in the feature tree dialog

**File association:** `.scef` files open with `scef-gui.exe`

**System PATH:** Install directory appended — `scef` CLI works in any new terminal

**VC++ 2022 Redistributable:** Installed silently if not already present

## Upgrade / Uninstall

- Installing a newer version automatically removes the older one (`MajorUpgrade`)
- Installing an older version is blocked with an error message
- Uninstall via **Add/Remove Programs** — removes all files, shortcuts, PATH entry, file association, and the HKLM/HKCU registry markers under `Software\MEPhI\SCEF`

## Ignored / Not Committed

`installer/.gitignore` excludes:
- `staging/` — ephemeral build output
- `cache/VC_redist.x64.exe` — downloaded at build time (~6 MB)
- `dist/*.msi` — built output
- `*.wixpdb` — WiX debug symbols
- `Harvest.wxs` — generated by heat at build time
- `*.wixobj` — compiler output

## Notes for Next Release

1. Embed an application icon in `scef-gui.exe`: add a `.rc` file in `gui/` with `IDI_ICON1 ICON "scef.ico"` and reference it in `gui/CMakeLists.txt` with `target_sources(scef-gui PRIVATE scef-gui.rc)`. Then remove `CmpIcon` from `Package.wxs` and change `DefaultIcon` to `[INSTALLFOLDER]scef-gui.exe,0`.
2. Code-sign the MSI: `signtool sign /fd SHA256 /tr http://timestamp.digicert.com dist\scef-X.Y.Z-x64.msi`
3. Update `Version` in `scef/CMakeLists.txt` — the build script reads it automatically.
