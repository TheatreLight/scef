#pragma once

#include <filesystem>
#include <string>

namespace scef {

// Returns the directory containing the currently running executable.
// Throws std::runtime_error on platform-specific failure.
std::filesystem::path getExecutableDir();

struct BrowserViewerCopyResult {
    bool        success;
    std::string errorMessage; // empty on success
};

// Copies <sourceDir>/index.html to <destDir>/index.html.
// Overwrites silently if destination already exists.
// Returns success=false with a descriptive error message if source is missing or copy fails.
// Does NOT log or print; caller decides how to surface the error.
BrowserViewerCopyResult copyBrowserViewer(const std::filesystem::path& sourceDir,
                                          const std::filesystem::path& destDir);

} // namespace scef
