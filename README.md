# SCEF — Self-contained Encrypted Container Format

C++20 / Qt 6 implementation of an encrypted USB container with a browser-based decryptor. MEPhI diploma project.

For architecture, container format, and module-level docs see [docs/README.md](docs/README.md).

## Prerequisites

| Tool | Version | Required for |
|------|---------|--------------|
| CMake | 3.21+ | All builds |
| Ninja or MSBuild | recent | All builds |
| C++20 compiler | MSVC 2022, Clang 16+, GCC 13+ | All builds |
| Python 3 | 3.8+ | Browser viewer (`BROWSER_VIEWER_BUILD=ON`, default) |
| Qt | 6.11.0 (msvc2022_64) | GUI (`SCEF_BUILD_GUI=ON`) |
| vcpkg | latest | Botan 3, nlohmann_json, GTest |

## vcpkg setup

The build expects vcpkg to be cloned **next to** the `scef/` directory:

```
<repo-root>/
├── scef/        ← this project
└── vcpkg/       ← sibling clone
```

The path is hard-wired in [CMakeLists.txt](CMakeLists.txt) as
`${CMAKE_CURRENT_SOURCE_DIR}/../vcpkg/scripts/buildsystems/vcpkg.cmake`.

### One-time bootstrap

```bash
# From <repo-root>/
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg

# Windows
.\bootstrap-vcpkg.bat

# Linux / macOS
./bootstrap-vcpkg.sh
```

### Install dependencies

Classic mode (no `vcpkg.json` manifest in this project):

```bash
# From <repo-root>/vcpkg/

# Windows
.\vcpkg.exe install botan nlohmann-json gtest --triplet x64-windows

# Linux
./vcpkg install botan nlohmann-json gtest --triplet x64-linux
```

CMake picks them up automatically via the toolchain file — no extra `-DCMAKE_PREFIX_PATH` needed for these three.

## Build

All commands assume the working directory is `scef/`.

### CLI + unit tests (Debug)

```bash
cmake -B build/debug -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build/debug
```

Produces `build/debug/scef[.exe]` and `build/debug/scef_unit_tests[.exe]`.

### CLI + GUI (Release)

```bash
cmake -B build/gui -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DSCEF_BUILD_GUI=ON \
      -DCMAKE_PREFIX_PATH=C:/Qt/6.11.0/msvc2022_64
cmake --build build/gui
```

Produces `build/gui/scef[.exe]` and `build/gui/scef-gui[.exe]`.

## CMake options

| Option | Default | Effect |
|--------|---------|--------|
| `SCEF_BUILD_TESTS` | `ON` | Build `scef_unit_tests` (requires GTest) |
| `SCEF_BUILD_GUI` | `OFF` | Build `scef-gui` (requires Qt 6.11) |
| `SCEF_BUILD_BROWSER_TESTS` | `OFF` | Build `generate_vectors` helper |
| `BROWSER_VIEWER_BUILD` | `ON` | Build `browser/dist/index.html` and copy it next to each binary (requires Python 3) |

Set `-DBROWSER_VIEWER_BUILD=OFF` to skip the browser viewer build entirely (no Python dependency). Note: at runtime the binary still tries to copy `index.html` next to a newly created container. If you build with the viewer disabled, pass `--no-browser-viewer` to `scef create` (or uncheck the option in the GUI) to avoid a missing-file error.

## Run tests

```bash
# Unit tests (GTest)
ctest --test-dir build/debug --output-on-failure

# Integration tests (Python pytest, drives the CLI binary)
cd tests/integration
pytest
```

## Troubleshooting

- **`Could NOT find Botan` / `nlohmann_json`** — vcpkg install incomplete, or vcpkg is not at `../vcpkg/` relative to `scef/`. Check the toolchain path in `CMakeLists.txt`.
- **`TARGET 'scef-gui' was not created in this directory`** — fixed; if you see this, your tree is out of date.
- **GUI configure: Qt6TaskTree / Vulkan warnings** — Qt-internal noise from `Qt6QmlAssetDownloaderPrivate`. Non-fatal; configure completes.
- **Python 3 not found during configure** — install it or build with `-DBROWSER_VIEWER_BUILD=OFF`.
