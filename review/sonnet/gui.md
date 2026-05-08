# SCEF Qt QML GUI Review

## Executive Summary

The GUI is a reasonable prototype-level implementation that successfully demonstrates the facade pattern: QML pages talk exclusively to `ScefController`, which in turn drives `scef_lib`. The separation is largely clean — no crypto code lives in the GUI layer and `FileManager` is never exposed to QML directly. Thread-handling via `QThread::create` plus `QPointer` guard is mostly correct, and `Botan::secure_vector<char>` is used to move password bytes off the heap on the C++ side as quickly as possible.

However, there are several problems that range from security-relevant to architecturally broken. The most serious: the password typed in `CreatePage` lives in `passwordField.text` — a plain QML `string` property — throughout the entire lifecycle of the page, including while the async crypto operation is running, and it is never cleared after `performCreate()`. The second cluster of issues is around a broken `openContainer` flow: `init()` (which does Argon2id KDF + HMAC verification) is called inside the worker thread, but only for `openContainer`; for `createContainer`, `fileManager_->init()` is called synchronously on the UI thread before `runAsync`, meaning any slow filesystem pre-allocation can block the UI. A third cluster concerns the progress-reporting state machine being duplicated across three pages with hard-coded English strings cross-compared between C++ and QML. The facade surface is slightly wider than needed (`PasswordStrengthEstimator` is heap-allocated and destroyed on every keystroke, `logDirPath` leaks an internal directory layout to QML) but these are minor.

The code is thesis-committee-presentable with targeted fixes. The most critical issues must be addressed before a real demo.

---

## Findings by Severity

### Critical

**[C-1] `ScefController.cpp:131` — `FileManager::init()` runs on the UI thread during `createContainer`**

`createContainer` calls `fileManager_->init(...)` synchronously before `runAsync`. According to `FileManager.h`, `init` with `create_new=true` creates and pre-allocates the container file to `sizeBytes`. For a 1 GB container on a USB drive this is a blocking filesystem operation that can take several seconds, freezing the Qt event loop and making the UI unresponsive (window stops redrawing, OS may flag the process as "not responding" on Windows).

`openContainer` does not have this problem — it passes `init` inside the lambda to the worker thread. `createContainer` needs the same treatment. The pre-validation comment in the code ("init checks size before creating file") is factually correct but incomplete: the spec says init also calls `createContainerFile()` which does the actual allocation. Move the entire `FileManager` construction, init, `setCipher`, and `setKdfParams` calls into the `workFn` lambda, catching exceptions there instead of synchronously.

Suggested refactor outline:

```cpp
runAsync(std::make_unique<FileManager>(),
    [paths, dir, sizeBytes, profile, cipher, kdfM, kdfT, kdfP,
     pwd = std::move(pwd)](FileManager* fm) {
        fm->init(paths, dir, sizeBytes, DEFAULT_MAX_TABLE_SIZE, true, pwd);
        fm->setCipher(cipher);
        // setKdfParams ...
        fm->write();
    },
    [this, dirQ]() { /* onSuccess */ });
```

---

**[C-2] `CreatePage.qml:44-57` and throughout — Password not cleared after `performCreate()`**

`performCreate()` reads `passwordField.text` and passes it directly to `controller.createContainer(...)`. The password string remains live in:
- `passwordField.text` for the entire duration of the async operation and until the user manually navigates away or clears it.
- The local JS variable `var error = controller.createContainer(...)` — though short-lived.
- When `weakPasswordDialog` fires `onAccepted: performCreate()`, the password in `passwordField.text` has been sitting there since before the dialog was opened.

`PasswordDialog` in `StartPage` correctly does `passwordDialog.password = ""` immediately after passing the value to C++. `CreatePage` never does the equivalent. Add `passwordField.text = ""; confirmPasswordField.text = ""` immediately after the value is consumed in `performCreate()`. This does not prevent the C++ layer from receiving the password because `createContainer` is synchronous at the call site (returns after launching the async thread).

Note: zeroing a QML `string` property does not guarantee secure erasure because Qt's `QString` is reference-counted and the underlying data may not be overwritten. This is the inherent limitation of the "Browser mode = reduced security" trade-off documented in the architecture. The C++ side correctly converts to `Botan::secure_vector<char>` and then the QML string should be cleared as early as possible to reduce the exposure window.

---

**[C-3] `StartPage.qml:278` — Hard-coded container filename with manual URL construction**

```qml
passwordDialog.containerPath = "file:///" + drivePath + "container.scef"
```

`drivePath` comes from `DriveListModel::pathAtRow()` which returns a string like `"E:\"`. The resulting URL is `file:///E:\container.scef` which contains a backslash. `toLocalPath()` in C++ parses this via `QUrl::toLocalFile()`. On Windows, Qt's URL parser handles `file:///E:\` erratically — forward slash vs backslash mixing after the drive letter is not guaranteed to round-trip correctly through QUrl. The existing `CONTAINER_FILE_NAME` constant in `FileManager.h` is never used here.

Fix: pass the raw filesystem path (not a URL) or use `Qt.resolvedUrl` / `QUrl::fromLocalFile` on the C++ side before calling `toLocalPath`. At minimum, replace the string concatenation with:

```qml
passwordDialog.containerPath = drivePath + "container.scef"
```

and rely on `toLocalPath`'s fallback path (`return urlOrPath.toStdString()`) for plain paths. Also use `CONTAINER_FILE_NAME` (exposed via a `Q_INVOKABLE` or constant on `ScefController`) instead of the magic string `"container.scef"` repeated in both C++ and QML.

---

### Major

**[M-1] `ScefController.cpp:391-423` — QThread created but never waited on; potential use-after-free if `QApplication` quits during async work**

`QThread::create` produces a thread that is started with `thread->start()` and connected to `deleteLater`. If the user closes the window while the worker is running, `QApplication::exec()` returns, the stack unwinds, `ScefController` is destroyed, and the worker thread is still alive. The `QPointer<ScefController> guard` protects emission of signals, but `fm` still captures a `std::function` lambda. If `qApp` is also destroyed by then, the `QMetaObject::invokeMethod(qApp, ...)` in the worker callback will dereference a dangling `qApp` pointer.

More concretely: the lambda inside the worker thread calls `QMetaObject::invokeMethod(qApp, ...)` — if `QApplication` has been destroyed, `qApp` is null and this is undefined behavior.

Fix: either install a `QCoreApplication::aboutToQuit` handler that sets a cancellation flag checked by the worker, or use `QThreadPool` with `QRunnable` and proper lifecycle management. At minimum, add a null check: `if (!qApp) return;` at the top of the inner lambda before the `QMetaObject::invokeMethod` call in the worker. For a diploma project the minimal fix is sufficient, but document the limitation.

---

**[M-2] `ScefController.h:85` / `ScefController.cpp:218` — `fileManager_` is null after `runAsync` returns; `addFiles`/`extractFiles` guard is incorrectly sequenced**

After `runAsync(std::move(fileManager_), ...)`, `fileManager_` is null (moved out). The checks `if (!fileManager_) return "No container is open"` at the top of `addFiles` and `extractFiles` correctly reject calls while `busy_`, but only because `busy_` is checked first. If `busy_` were ever false while `fileManager_` is null (e.g., after a failed `openContainer` where `onSuccess` was never called), the null check catches it. This is correct but fragile: the two guards are semantically coupled — `busy_` being false implies `fileManager_` is restored. Add a comment explicitly documenting this invariant, or unify into a single state enum (`Idle`, `Busy`, `Open`) to make the state machine explicit.

---

**[M-3] `FileListPage.qml:181-184` — Manual `selectedIndicesChanged()` call on a plain `var` property**

```qml
property var selectedIndices: ({})
...
var copy = selectedIndices
copy[index] = checked
selectedIndices = copy
selectedIndicesChanged()
```

The `selectedIndicesChanged()` call is redundant and wrong: assigning `selectedIndices = copy` already emits `selectedIndicesChanged` automatically because it replaces the property value. The explicit call emits the signal a second time, causing every binding on `selectedIndices` (including `checked: !!selectedIndices[index]` on every visible delegate) to re-evaluate twice per checkbox toggle. With large file lists this is an O(n) double-evaluation per interaction.

Additionally `selectedIndices = {}` on line 327 is followed immediately by `selectedIndicesChanged()` — same double-emission.

Remove all explicit `selectedIndicesChanged()` calls. If the intent was to force re-evaluation because object mutation (not replacement) was used, the current code already does replacement (`selectedIndices = copy`), so the signal fires once automatically.

---

**[M-4] `ScefController.cpp:168-183` — `estimatePasswordStrength` is called synchronously on every "Create" button click and allocates a `PasswordStrengthEstimator` on the heap each time**

`estimatePasswordStrength` is `const` and `Q_INVOKABLE`, which is fine. But it constructs a `PasswordStrengthEstimator` per call. Looking at the `PasswordStrengthEstimator` header, the constructor/destructor are non-trivial (they are declared without `= default`), suggesting internal state or library initialization. If the estimator is called on every key press in a future version, this becomes a per-keystroke allocation. More importantly for correctness: the password string passed in is a `const QString&`, converted to `secure_vector<char>` inside the function, and that conversion allocates. This is unavoidable. But the `PasswordStrengthEstimator` itself should be a member of `ScefController` (constructed once) rather than a local. This is a minor resource concern now but the pattern is wrong for extension.

---

**[M-5] `DriveListModel.cpp:75-128` — `refresh()` is synchronous and calls Win32 I/O APIs + `std::filesystem::exists` on the UI thread**

`GetDiskFreeSpaceExW`, `GetVolumeInformationW`, and `std::filesystem::exists` can block for hundreds of milliseconds on slow or unmounted USB drives. `refresh()` is called from `Component.onCompleted` in `StartPage` and from the "Refresh" button. Since it resets the model synchronously, any blocking inside it freezes the UI. For a diploma prototype this is tolerable, but it should be documented and ideally moved to a background thread using the same `runAsync` pattern (or a simpler `QtConcurrent::run`).

Also: `std::filesystem::exists(containerPath)` is called inside `refresh()` for each drive. If a drive is momentarily unresponsive (network-mapped, ejecting), this can throw. There is no exception handler around this call. Add `try/catch(const std::filesystem::filesystem_error&)`.

---

**[M-6] `CreatePage.qml:123-126` — URL-to-path decoding in QML with hand-rolled regex**

```qml
text: "Destination: " + decodeURIComponent(
    initialDestDir.replace(/^file:\/\/\//, "").replace(/^file:\/\//, ""))
```

This manually strips URL prefixes to produce a display path. It will produce incorrect results on Windows UNC paths (`\\server\share`), paths with non-ASCII characters (percent-encoded sequences), and paths that are already plain filesystem paths (no `file://` prefix). The C++ layer already has `toLocalPath()` which handles this correctly via `QUrl::toLocalFile()`. Expose a `Q_INVOKABLE QString toDisplayPath(const QString& urlOrPath)` on `ScefController` and use it here, or just display `initialDestDir` without transformation since it is only for display.

---

**[M-7] `ScefController.cpp:302` — Mix of `QString::fromUtf8("[cannot open: ")` and `QStringLiteral("]")` in `readLogFile`**

```cpp
return QString::fromUtf8("[cannot open: ") + path + QStringLiteral("]");
```

`QString::fromUtf8` on a string literal with no non-ASCII characters is equivalent to `QStringLiteral` but allocates at runtime and does UTF-8 conversion. The inconsistency with the surrounding code (which uses `QStringLiteral` everywhere else) is a style error that could indicate copy-paste confusion. Use `QStringLiteral` consistently.

The same line on 308: `return QStringLiteral("[cannot seek: ") + path + QStringLiteral("]");` is correct. Line 302 is not.

---

### Minor

**[m-1] `Main.qml:5-43` — Components declared in root Window scope are instantiated at startup, not lazily**

```qml
Component { id: startPage; StartPage {} }
Component { id: createPage; CreatePage {} }
Component { id: fileListPage; FileListPage {} }
Component { id: logsPage; LogsPage {} }
```

`Component` elements in QML are lazy by design — the child item is not instantiated until the component is used. This is correct. However, `StackView.initialItem: startPage` uses the `startPage` component immediately, which means `StartPage` is created at startup (correct). The other three components are indeed lazy. No bug here, but naming all four as top-level sibling components with non-descriptive IDs (`startPage`, `createPage`, etc.) means any page can navigate to any other page via `stackView` without StackView controlling ownership. This is a design pattern choice, not a bug, but worth noting that popping `FileListPage` does not call `closeContainer` — it relies on the explicit `controller.closeContainer()` call in the button handler.

**[m-2] `StartPage.qml:203` — Emoji rendered as a QML `Label` with Unicode surrogate pair**

```qml
Label { text: "🔌" }
```

`🔌` is a UTF-16 surrogate pair for the plug emoji (U+1F50C). In QML string literals this may or may not render correctly depending on the Qt version and platform font. Qt 6 handles this, but a Unicode font must be installed and the rendering is font-dependent. For a thesis demo on an examiner's machine with a CJK-only system font this will render as a box. Use a text character (`[=]`, `[USB]`) or a Qt resource icon instead. This is a cosmetic concern but fails on some configurations.

**[m-3] `CreatePage.qml:37-38`, `StartPage.qml:20-26` — Progress stage strings compared between QML and C++ as magic strings**

```qml
if (progressStage === "Encrypting data..." || progressStage === "Decrypting data...")
```

The progress label strings are defined in `ScefController.cpp::progressStageLabel()` as `QStringLiteral("Encrypting data...")`. QML pages compare against these strings to decide whether to show a percentage. If the C++ string is ever changed (typo fix, localization), the QML condition silently breaks. This is a maintenance trap.

Fix: expose `progressStage` as a typed enum Q_PROPERTY on `ScefController`, or emit a separate `progressFractionVisible` bool alongside `progressChanged`. The current design forces QML to peek into internal C++ string values.

**[m-4] `ScefController.h:26` — `Q_PROPERTY(QString currentContainerPath ...)` notifies on `containerOpenChanged`**

```cpp
Q_PROPERTY(QString currentContainerPath READ currentContainerPath NOTIFY containerOpenChanged)
```

`currentContainerPath` changes whenever a container is opened or closed, which does coincide with `containerOpenChanged`. But if a future path exists where `currentContainerDir_` changes without `containerOpenChanged` being emitted (e.g., container path re-resolved), the binding will be stale. Give `currentContainerPath` its own `currentContainerPathChanged` signal to follow the single-responsibility principle for NOTIFY signals.

**[m-5] `LogsPage.qml:24` — `readLogFile` is called on UI thread and reads up to 1 MiB synchronously**

`controller.readLogFile(path)` with a default `maxBytes=1048576` reads up to 1 MiB of log content synchronously on the UI thread. For small log files this is fine. For a production tool it should be async. For a diploma demo, document it.

**[m-6] `CreatePage.qml:61-67` — KDF profile index mapping is duplicated between QML and C++**

QML defines:
```qml
readonly property var kdfProfiles: [
    { label: "Standard ...", m: 1024, t: 1, p: 4 },  // index 0 → Standard
    { label: "Fast ...",     m: 256,  t: 1, p: 4 },  // index 1 → Fast
    { label: "High ...",     m: 2048, t: 1, p: 4 },  // index 2 → High
    { label: "Browser ...", m: 64,   t: 1, p: 1 },  // index 3 → Browser
]
```

C++ `profileFromIndex`:
```cpp
case 0: return EKDFProfile::Standard;
case 1: return EKDFProfile::Fast;
case 2: return EKDFProfile::High;
case 3: return EKDFProfile::Browser;
```

The mapping is maintained in two places. If the QML array order is changed, the wrong profile is silently selected. The C++ `KdfProfiles.h` already has a `KdfProfileParams` table. Expose the profile list to QML via a `Q_INVOKABLE QVariantList kdfProfileList()` on the controller so QML drives iteration from a single authoritative source.

**[m-7] `FileListPage.qml:86` — `selectedFolder` (a `QUrl`) passed directly to `controller.extractFiles`**

```qml
var error = controller.extractFiles(names, selectedFolder)
```

`selectedFolder` is a `QUrl` property of `FolderDialog`. Passing a `QUrl` where `extractFiles` expects a `QString` works because QML will call `QUrl::toString()` on the `QUrl` before crossing the boundary, producing a `file:///...` URL string. `toLocalPath` in C++ then correctly converts it. But the intent is not obvious. It is cleaner to write `selectedFolder.toString()` explicitly (as `StartPage.qml:107` already does with `selectedFolder.toString()`), or pass `selectedFolder.toLocalFile()`. The inconsistency between `FileListPage.qml:86` (implicit) and `StartPage.qml:107` (explicit `.toString()`) is a maintenance hazard.

**[m-8] `ScefController.h:32-40` — `createContainer` signature has 9 parameters**

A 9-parameter public Q_INVOKABLE is hard to maintain and impossible to mock in tests. Consider grouping `kdfProfileIndex`, `kdfM_MiB`, `kdfT`, `kdfP`, `cipherIndex` into a `QVariantMap` or a dedicated `Q_GADGET` struct. This reduces the QML call site from a 9-argument positional call to a readable named structure.

**[m-9] `CMakeLists.txt:1` — `find_package(Qt6 6.5 REQUIRED ...)` specifies minimum version 6.5 but project uses Qt 6.11.0**

The minimum version constraint is `6.5`. The project uses `6.11.0`. This is not a bug — any version >= 6.5 will satisfy the constraint. But it means the build will attempt to compile against Qt 6.5 if that is what is found, and Qt 6.5 may not have all APIs used (e.g., `QQmlApplicationEngine::objectCreationFailed` was added in 6.4, so 6.5 is fine). Still, explicitly setting the minimum to `6.8` or `6.9` (the actual development baseline) prevents accidental builds against older Qt versions that may have subtle differences. Also: `PasswordStrengthEstimator.h` is in `include/` but `PasswordStrengthEstimator.h` is not listed in `CMakeLists.txt`'s `SOURCES` — it is presumably pulled in via the `scef_lib` linkage. Confirm this is intentional.

**[m-10] `ScefController.cpp:44-48` — `securePasswordFromQString` copies UTF-8 bytes into `secure_vector<char>` but the intermediate `QByteArray` is not scrubbed**

```cpp
const QByteArray utf8 = password.toUtf8();
return Botan::secure_vector<char>(utf8.constData(), utf8.constData() + utf8.size());
```

`utf8` is a heap-allocated `QByteArray` that contains the password in plaintext. It goes out of scope and its destructor calls `delete[]` but does not overwrite the memory. Botan provides `Botan::secure_scrub_memory` for exactly this purpose. The window is narrow (local scope), but for a security-critical application:

```cpp
Botan::secure_vector<char> securePasswordFromQString(const QString& password)
{
    const QByteArray utf8 = password.toUtf8();
    Botan::secure_vector<char> result(utf8.constData(), utf8.constData() + utf8.size());
    Botan::secure_scrub_memory(
        const_cast<char*>(utf8.constData()), static_cast<size_t>(utf8.size()));
    return result;
}
```

This is a minor improvement because `QByteArray::constData()` returns a `const char*` requiring a cast, and `QByteArray` may COW-detach internally. Document the limitation.

---

### Nitpick

**[N-1] `Main.qml` — Window title uses a dash that is not a proper em-dash**

`title: "SCEF - Encrypted Container Manager"` — consider `"SCEF — Encrypted Container Manager"` for typographic correctness in a thesis demo. Optional.

**[N-2] `CreatePage.qml:342-356` — `MouseArea` inside a `Label` for toggle instead of a `Button {flat: true}`**

The "Advanced KDF Settings" toggle uses `MouseArea` over a `Label`. This bypasses Material ripple effects, keyboard navigation, and accessibility. A `Button { flat: true; text: "..." }` provides the same visual result with proper Material behavior.

**[N-3] `StartPage.qml:272` — `enabled: ... && driveListRevision >= 0` is always true**

```qml
enabled: selectedDriveIndex >= 0 && driveListRevision >= 0
         && controller.driveListModel.hasContainerAtRow(selectedDriveIndex)
```

`driveListRevision` starts at `0` and only increments. The condition `driveListRevision >= 0` is a tautology. The apparent intent was to force QML to re-evaluate the binding when the model resets, but this already happens because `selectedDriveIndex` is reset to `-1` on refresh. Remove the dead clause.

**[N-4] `ScefController.h` — `PasswordStrengthEstimator.h` included in the header**

`PasswordStrengthEstimator` is used only in `ScefController.cpp` in the body of `estimatePasswordStrength`. Including its header in `ScefController.h` forces it to be transitively included by every TU that includes `ScefController.h`. Move the include to `ScefController.cpp` and forward-declare or just remove the class-level member (since `estimatePasswordStrength` constructs it locally anyway).

**[N-5] `LogsPage.qml:11-14` — `currentPath()` function guards `fileCombo.model` with `!fileCombo.model` but model is always an array**

The guard is `if (!fileCombo.model || ...)`. A `ComboBox.model` set to an array is truthy unless it is explicitly `null` or `undefined`. The guard is defensive noise that would never trigger in practice given the code paths. Simplify to just the index bounds check.

---

## Dead Code & Unused Symbols

**`PasswordStrengthEstimator` member field not present.** `ScefController.h` includes `PasswordStrengthEstimator.h`, but the class has no `PasswordStrengthEstimator` member field — it is constructed locally in `estimatePasswordStrength`. The include is therefore pulling in a header purely for a function-local use. This is not dead code per se, but the include is misplaced (see N-4).

**`progressStageLabel(ProgressStage::Done)` returns `"Done"` which is never displayed.** The `Done` stage emits `progressChanged("Done", 1.0)` but no QML page has a handler that shows this — by the time `Done` fires, `operationFinished` fires next and the busy overlay is dismissed. The label `"Done"` is computed and immediately discarded.

**`driveListRevision` in `StartPage.qml`.** As noted in N-3, it serves no functional purpose in the `enabled` expression. It also increments on every `onModelReset` signal, accumulating without bound. Since QML integers are doubles (float64), overflow is not a practical concern, but the variable is semantically dead.

---

## C++/QML Boundary Issues

### Types Crossing the Boundary

`FileListModel` and `DriveListModel` are registered as `QAbstractListModel` subclasses and exposed to QML via `Q_PROPERTY CONSTANT`. This is correct Qt practice and the models are owned by `ScefController` (parent chain), so lifetime is safe.

`QVariantMap` returned by `estimatePasswordStrength` is the correct approach for ad-hoc structured data crossing the boundary. The keys (`"score"`, `"bits"`, etc.) are `QStringLiteral` in C++ but accessed as bare string properties in QML (`strength.meetsRecommendation`). This is fine — QML maps QVariantMap keys to JS object properties automatically.

### Error-Channel Design

All `Q_INVOKABLE` methods that can fail return `QString` — empty on success, error message on failure. This is a pragmatic design for a project of this size. The limitation is that callers cannot distinguish error categories (wrong password vs. I/O error vs. container too small) — they get raw `std::exception::what()` strings from C++. For the thesis prototype this is acceptable, but it should be documented as a known limitation if the committee asks why error handling is string-based.

`operationFinished(const QString& error)` signal follows the same convention for async operations. The convention is consistent across all operations.

### Q_PROPERTY Usage

`Q_PROPERTY(FileListModel* fileListModel READ fileListModel CONSTANT)` — correct. A `CONSTANT` property means QML will not set up change tracking, which is fine since the model pointer never changes (only its contents change, which the model notifies itself).

`Q_PROPERTY(bool containerOpen ...)` and `Q_PROPERTY(bool busy ...)` — correct, with NOTIFY. Both use single signals per property, which is standard.

`Q_PROPERTY(QString currentContainerPath ... NOTIFY containerOpenChanged)` — see [m-4] above. Functionally correct but semantically imprecise.

`Q_PROPERTY(bool benchEnabled READ benchEnabled WRITE setBenchEnabled NOTIFY benchEnabledChanged)` — correct two-way binding. The setter delegates to `Logger::setBenchEnabled`, which is a global state mutation. If two `ScefController` instances ever existed (unlikely in this design), they would share Logger state but each emit their own `benchEnabledChanged`. Not a real risk here.

### Blocking Calls

Identified blocking calls on the UI thread:
1. `createContainer` → `fileManager_->init()` — **Critical** (see C-1).
2. `DriveListModel::refresh()` → Win32 I/O — **Major** (see M-5).
3. `ScefController::readLogFile()` → `QFile::read(1 MiB)` — Minor.
4. `ScefController::estimatePasswordStrength()` — computationally cheap; acceptable on UI thread.

---

## QML/UX Issues

### Theme Consistency

The Material Dark theme is applied at the Window level (`Material.theme: Material.Dark`, `Material.primary: Material.Red`, `Material.accent: Material.LightGreen`). All child items inherit this correctly. However:

- `errorLabel.color: "red"` (plain string) in `StartPage`, `CreatePage`, and `FileListPage` should be `Material.color(Material.Red)` to stay within the Material palette and respect dark/light variants.
- `successLabel.color: "lightgreen"` should be `Material.color(Material.LightGreen)`.
- The title `Label` in `StartPage` and other pages uses `color: Material.color(Material.Amber)` — this is consistent across pages (good), but Amber is not the declared `primary` or `accent` color. It works visually but is a third undeclared accent color. The style reference project (`noctfold`) presumably uses Amber for titles; if so, document it in a comment.

### Navigation

Navigation is pure push/pop on a single StackView. The Back buttons call `stackView.pop()` or `stackView.pop(null)`. `pop(null)` pops to the bottom of the stack (StartPage), while `pop()` pops one level. `CreatePage` uses `pop(null)` (correct — go all the way back to start after success), while `LogsPage` and `FileListPage.Back` button use `pop()` (correct — one level back). This is consistent.

There is no way to reach `FileListPage` from `LogsPage`, and `LogsPage` is reachable from both `StartPage` and `FileListPage`. If the user navigates `StartPage → LogsPage → Back`, they are back at `StartPage`. If they navigate `FileListPage → LogsPage → Back`, they are back at `FileListPage`. This is correct behavior for a stack.

However: `LogsPage` and `FileListPage` both call `stackView.push(logsPage)` referencing the `logsPage` Component defined in `Main.qml`. This works because of QML's implicit parent scope resolution — all pages can see `stackView` and `logsPage` via the parent window scope. This is an implicit dependency that could silently break if any page is reused outside `Main.qml`. Make the dependency explicit (pass `stackView` as a required property or use a Navigator pattern) for robustness.

### Focus and Accessibility

- `PasswordDialog` correctly calls `passwordField.forceActiveFocus()` on `onOpened`. Good.
- `CreatePage` does not set initial focus to `passwordField` when the page is pushed. The user has to click the password field. Add `Component.onCompleted: passwordField.forceActiveFocus()`.
- The "Advanced KDF Settings" toggle is a `MouseArea` inside a `Label` — not keyboard-navigable (see N-2).
- No `Accessible.name` or `Accessible.description` properties on any interactive element. For a thesis demo this is acceptable, but it is worth mentioning if the committee asks about accessibility.
- `CheckBox` delegates in `FileListPage` have no visible label — only the file name label beside them. The checkbox role is clear visually but is not described to screen readers.

### Minor UX Issues

- The busy overlay in `CreatePage` and `FileListPage` is a semi-transparent `Rectangle` that blocks interaction (`z: 10`). It does not block keyboard shortcuts or `Alt+F4`. This is acceptable for a prototype but should be noted.
- `sizeSpin.from: 1` allows a 1 MB container. The spec requires a minimum of ~272 KiB. A 1 MB container is above the minimum, but the backend will throw if the size cannot fit 4 slots + metadata. The error surfaces via `operationFinished`, which is adequate.
- The success overlay in `CreatePage` auto-dismisses after 1500 ms. If the machine is slow and the dismiss timer fires before the user reads it, they may not see confirmation. Consider using a `SnackBar` pattern or a persistent status label.

---

## Verdict

**CHANGES_REQUESTED.** The following must be addressed:

1. **[C-1]** Move `FileManager::init()` inside `runAsync`'s worker lambda in `createContainer`. Blocking the UI thread during filesystem pre-allocation is the most user-visible bug and will cause "not responding" on Windows with large containers.

2. **[C-2]** Clear `passwordField.text` and `confirmPasswordField.text` immediately after their value is consumed in `performCreate()`. The password must not outlive the hand-off to `securePasswordFromQString`.

3. **[C-3]** Fix the drive path → container URL construction in `StartPage.qml:278`. Replace the manual `"file:///" + drivePath + "container.scef"` with a plain path string, and eliminate the magic string `"container.scef"` duplicated between C++ and QML.

4. **[M-1]** Guard against `qApp == nullptr` in the worker thread's queued callback. Document the window-close-during-operation limitation explicitly.

5. **[M-3]** Remove the redundant manual `selectedIndicesChanged()` calls in `FileListPage.qml`. Each assignment already emits the signal once; the explicit calls cause double-evaluation of all delegate bindings.
