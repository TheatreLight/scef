#include "BrowserViewer.h"

#include <stdexcept>
#include <system_error>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace scef {

std::filesystem::path getExecutableDir()
{
#ifdef _WIN32
    std::wstring buffer(MAX_PATH, L'\0');

    for (;;) {
        const DWORD length = GetModuleFileNameW(
            nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (length == 0) {
            throw std::runtime_error("GetModuleFileNameW failed");
        }

        if (length < buffer.size()) {
            buffer.resize(length);
            return std::filesystem::path(buffer).parent_path();
        }

        buffer.resize(buffer.size() * 2);
    }
#else
    std::vector<char> buffer(4096);

    for (;;) {
        const ssize_t length = readlink("/proc/self/exe", buffer.data(), buffer.size() - 1);
        if (length < 0) {
            throw std::runtime_error("readlink(/proc/self/exe) failed");
        }
        if (static_cast<size_t>(length) < buffer.size() - 1) {
            buffer[static_cast<size_t>(length)] = '\0';
            return std::filesystem::path(buffer.data()).parent_path();
        }
        buffer.resize(buffer.size() * 2);
    }
#endif
}

BrowserViewerCopyResult copyBrowserViewer(const std::filesystem::path& sourceDir,
                                          const std::filesystem::path& destDir)
{
    const auto source = sourceDir / "index.html";
    const auto dest   = destDir / "index.html";

    std::error_code ec;
    if (!std::filesystem::exists(source, ec)) {
        if (ec) {
            return {false, "cannot check browser viewer source '" + source.string() +
                               "': " + ec.message()};
        }
        return {false, "browser viewer source is missing: " + source.string()};
    }

    if (!std::filesystem::is_regular_file(source, ec)) {
        if (ec) {
            return {false, "cannot inspect browser viewer source '" + source.string() +
                               "': " + ec.message()};
        }
        return {false, "browser viewer source is not a regular file: " + source.string()};
    }

    if (!destDir.empty()) {
        std::filesystem::create_directories(destDir, ec);
        if (ec) {
            return {false, "cannot create destination directory '" + destDir.string() +
                               "': " + ec.message()};
        }
    }

    if (std::filesystem::equivalent(source, dest, ec)) {
        return {true, {}};
    }
    ec.clear();

    std::filesystem::copy_file(source, dest,
                               std::filesystem::copy_options::overwrite_existing,
                               ec);
    if (ec) {
        return {false, "cannot copy browser viewer to '" + dest.string() +
                           "': " + ec.message()};
    }

    return {true, {}};
}

} // namespace scef
