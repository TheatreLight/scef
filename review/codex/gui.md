# SCEF Qt QML GUI Review — Codex

Files reviewed:
- scef/gui/main.cpp
- scef/gui/ScefController.h
- scef/gui/ScefController.cpp
- scef/gui/FileListModel.h
- scef/gui/FileListModel.cpp
- scef/gui/DriveListModel.h
- scef/gui/DriveListModel.cpp
- scef/gui/CMakeLists.txt
- scef/gui/qml/Main.qml
- scef/gui/qml/StartPage.qml
- scef/gui/qml/CreatePage.qml
- scef/gui/qml/FileListPage.qml
- scef/gui/qml/PasswordDialog.qml
- scef/gui/qml/LogsPage.qml
- scef/gui/utils.js

## Summary

The GUI follows the intended facade/model shape and already moves core crypto/file operations off the UI thread, but several security and lifetime edges are not safe enough for an encrypted-storage application. The main risks are password copies in unmanaged UI memory, unsafe drive-string conversion, weak worker-thread shutdown semantics, and broken state recovery after async failures.

## Issues

### CRITICAL Unsafe WideCharToMultiByte buffer sizing can corrupt memory
**File:** scef/gui/DriveListModel.cpp:91
**What:** `needed` includes the terminating NUL, but `letterStr` is allocated with `needed - 1` bytes and then `WideCharToMultiByte(..., letterStr.data(), needed, ...)` writes `needed` bytes. The same pattern exists for volume labels at lines 99-101.
**Why it matters:** This can write past the string size and cause memory corruption or crashes during drive enumeration.
**Fix:** Use `QString::fromWCharArray(current).toStdString()` / `QString::fromWCharArray(volumeName).toStdString()`, or allocate `needed` bytes, check `needed > 0`, then remove the trailing NUL after conversion.

### CRITICAL Password plaintext remains in QML/QString/QByteArray memory
**File:** scef/gui/ScefController.cpp:46
**What:** `password.toUtf8()` creates a normal `QByteArray` containing the password and it is not scrubbed. QML also keeps passwords in `TextField.text`/JS strings, especially `CreatePage.qml:48`, `PasswordDialog.qml:13`, and `StartPage.qml:132`.
**Why it matters:** The native GUI does not meet the stated password-lifetime requirement; plaintext passwords can remain in ordinary heap memory until allocator reuse or QML GC.
**Fix:** Clear QML fields immediately after handoff, avoid aliasing password text longer than needed, scrub the temporary `QByteArray` after copying into `secure_vector`, and consider moving password capture into C++ where the buffer lifetime can be controlled.

### CRITICAL Worker threads are not owned, joined, or cancelled on shutdown
**File:** scef/gui/ScefController.cpp:381
**What:** `runAsync()` creates an unparented `QThread`, the controller destructor is defaulted, and no active worker is joined or cancelled if the window/app closes during create/add/extract.
**Why it matters:** Closing the GUI during a write can terminate the process while container metadata/data is being updated, risking corruption; queued callbacks may also be dropped during application shutdown.
**Fix:** Store the active worker/thread as controller state, connect cleanup before starting, block or handle window close while busy, and implement orderly cancel/wait semantics in `~ScefController()`.

### MAJOR Open File ignores the selected container filename
**File:** scef/gui/ScefController.cpp:190
**What:** `openContainer()` receives `containerPath`, but only uses `fi.absolutePath()` and calls `FileManager::init(..., dir, ...)`, whose contract opens `dir + "/container.scef"`.
**Why it matters:** The manual file picker accepts arbitrary `*.scef` files, but the GUI will open `container.scef` in the same folder instead of the file the user selected.
**Fix:** Either extend `FileManager`/facade to accept an exact container file path, or restrict the UI to selecting a directory/drive and clearly require the fixed `container.scef` filename.

### MAJOR Async failure loses the open FileManager but leaves GUI state open
**File:** scef/gui/ScefController.cpp:409
**What:** On any worker error, `fm.reset()` is called and `fileManager_` is not restored, but `containerOpen_`, `currentContainerDir_`, and the file list are left unchanged.
**Why it matters:** A failed add/extract can leave the UI showing an open container that can no longer be used; later operations return "No container is open".
**Fix:** For operations on an already open container, return `fm` to `fileManager_` even on recoverable errors, or explicitly close the container, clear the model, and emit `containerOpenChanged()`.

### MAJOR Drive refresh blocks the UI thread and can leave model reset unbalanced
**File:** scef/gui/DriveListModel.cpp:70
**What:** `refresh()` runs WinAPI calls and `std::filesystem::exists()` synchronously from QML, inside `beginResetModel()`/`endResetModel()`.
**Why it matters:** Slow or faulty removable drives can freeze the UI; exceptions from filesystem access can skip `endResetModel()` and corrupt the model state.
**Fix:** Enumerate drives on a worker thread into a temporary vector, use non-throwing filesystem APIs with `std::error_code`, then apply the model reset on the GUI thread.

### MAJOR Q_INVOKABLE input validation relies on QML controls
**File:** scef/gui/ScefController.cpp:141
**What:** Custom KDF values are cast from `int` to `uint32_t` without C++ range checks; negative values become huge. `sizeMB` multiplication at line 115 also has no facade-level bounds check.
**Why it matters:** QML constraints are not a security boundary. Bad invokable inputs can cause excessive Argon2 memory use, denial of service, or invalid container creation.
**Fix:** Validate `sizeMB`, memory, iterations, parallelism, profile index, and cipher index in C++ before constructing `FileManager`.

### MAJOR Create page can navigate away while creation is busy
**File:** scef/gui/qml/CreatePage.qml:458
**What:** The Back button is not disabled during `controller.busy`, and the busy overlay is a plain `Rectangle` without modal input handling.
**Why it matters:** If the page is popped while creation is running, the page-scoped `Connections` can miss `operationFinished`; the success handler that closes the created container may never run.
**Fix:** Disable all navigation while busy, make the overlay consume input or use a modal `Popup/Dialog`, and keep operation-result handling tied to an operation token rather than page visibility alone.

### MAJOR Log reader exposes arbitrary local file reads to QML
**File:** scef/gui/ScefController.cpp:294
**What:** `readLogFile(path)` opens any path passed from QML without canonicalizing it under `logDirPath()`.
**Why it matters:** The current LogsPage passes listed log paths, but the public invokable is broader than necessary and can read unrelated local files if called from QML.
**Fix:** Accept a log filename/index instead of a raw path, canonicalize it, and reject anything outside the configured log directory.

### MINOR Non-Windows drive enumeration is unimplemented
**File:** scef/gui/DriveListModel.cpp:126
**What:** The non-Windows branch returns an empty list.
**Why it matters:** The GUI builds cross-platform, but the primary removable-drive workflow silently disappears outside Windows.
**Fix:** Use `QStorageInfo` for a portable baseline and keep WinAPI-specific enrichment behind `_WIN32`.

### MINOR Hardcoded colors and sizes bypass the Material theme
**File:** scef/gui/qml/CreatePage.qml:267
**What:** Several QML files use hardcoded colors such as `"#FF0000"`, `"red"`, `"orange"`, `"lightgreen"`, and many repeated dimensions.
**Why it matters:** This weakens Material Dark consistency and makes accessibility/contrast tuning harder.
**Fix:** Centralize theme constants and use `Material.color(...)`/semantic properties for error, warning, success, spacing, and common widths.

### MINOR Controller logic is hard to unit-test in isolation
**File:** scef/gui/ScefController.cpp:130
**What:** The controller directly constructs `FileManager` and `QThread::create()` workers.
**Why it matters:** Async success/failure paths, error translation, and state transitions require full GUI/core integration to test.
**Fix:** Introduce small injectable seams for a `FileManager` factory and async executor, then cover controller state transitions with Qt unit tests.

## Positive Notes
- The GUI uses the intended facade pattern: QML talks to `ScefController`, and list data is exposed through `QAbstractListModel`.
- `FileListModel` and `DriveListModel` implement `rowCount`, `data`, and `roleNames` correctly in normal paths.
- Heavy `FileManager` operations are designed to run outside the GUI thread, with progress marshalled back through queued Qt calls.
- QObject parent ownership is mostly correct for the controller-owned models.

## Verdict
CHANGES_REQUESTED
