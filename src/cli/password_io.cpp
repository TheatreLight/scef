#include "password_io.h"

#include "Logger.h"

#include <botan/mem_ops.h>

#include <iostream>
#include <stdexcept>

#ifdef _WIN32
#include <cstdlib>
#include <windows.h>
#ifdef ERROR
#undef ERROR
#endif
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace {

// RAII guard that disables terminal echo on construction and restores it
// on destruction. Terminal-specific; not exposed in the header.
class PasswordEchoGuard {
public:
    PasswordEchoGuard() {
#ifdef _WIN32
        handle_ = GetStdHandle(STD_INPUT_HANDLE);
        if (handle_ == INVALID_HANDLE_VALUE || handle_ == nullptr) {
            return;
        }
        DWORD mode = 0;
        if (!GetConsoleMode(handle_, &mode)) {
            return;
        }
        oldMode_ = mode;
        restore_ = SetConsoleMode(handle_, mode & ~ENABLE_ECHO_INPUT) != 0;
#else
        if (isatty(fileno(stdin)) == 0) {
            return;
        }
        if (tcgetattr(fileno(stdin), &oldTerm_) != 0) {
            return;
        }
        termios noEcho = oldTerm_;
        noEcho.c_lflag &= ~ECHO;
        restore_ = tcsetattr(fileno(stdin), TCSAFLUSH, &noEcho) == 0;
#endif
    }

    ~PasswordEchoGuard() {
#ifdef _WIN32
        if (restore_) {
            SetConsoleMode(handle_, oldMode_);
        }
#else
        if (restore_) {
            tcsetattr(fileno(stdin), TCSAFLUSH, &oldTerm_);
        }
#endif
    }

    bool disabledEcho() const noexcept { return restore_; }

private:
    bool restore_ = false;
#ifdef _WIN32
    HANDLE handle_ = nullptr;
    DWORD oldMode_ = 0;
#else
    termios oldTerm_{};
#endif
};

} // namespace

namespace cli {

// Read a password from stdin (up to the first newline or EOF).
// On Windows, the bytes delivered by std::cin use the active console input code page
// (GetConsoleCP()), which may differ from UTF-8 for non-ASCII characters.  The browser
// viewer always encodes the password as UTF-8 (hash-wasm uses TextEncoder internally),
// so we convert to UTF-8 here to ensure both paths hash the same byte sequence.
Botan::secure_vector<char> read_password()
{
    PasswordEchoGuard echoGuard;
    Botan::secure_vector<char> pw;
    char ch = '\0';
    while (std::cin.get(ch)) {
        if (ch == '\n' || ch == '\r') {
            break;
        }
        pw.push_back(ch);
    }
    if (echoGuard.disabledEcho()) {
        std::cerr << '\n';
    }
    if (pw.empty()) {
        throw std::runtime_error("Password cannot be empty");
    }

#ifdef _WIN32
    // Convert from the active console input code page to UTF-8 so that non-ASCII
    // passwords produce the same byte sequence as the browser viewer.
    const UINT cp = GetConsoleCP();
    if (cp != CP_UTF8) {
        // Step 1: CP → UTF-16.
        const int wlen = MultiByteToWideChar(
            cp, 0,
            pw.data(), static_cast<int>(pw.size()),
            nullptr, 0);
        if (wlen <= 0) {
            // Conversion failed — fall back to raw bytes and warn.
            LOG_WARN("read_password: MultiByteToWideChar failed (cp=%u, err=%lu); "
                     "non-ASCII passwords may not match browser viewer",
                     cp, GetLastError());
        } else {
            // Use a raw buffer so we can scrub it explicitly.
            auto* wbuf = static_cast<wchar_t*>(
                std::malloc(static_cast<size_t>(wlen) * sizeof(wchar_t)));
            if (!wbuf) {
                throw std::runtime_error(
                    "read_password: out of memory during CP→UTF-16 conversion");
            }
            MultiByteToWideChar(cp, 0, pw.data(), static_cast<int>(pw.size()), wbuf, wlen);

            // Step 2: UTF-16 → UTF-8.
            const int u8len = WideCharToMultiByte(
                CP_UTF8, 0,
                wbuf, wlen,
                nullptr, 0,
                nullptr, nullptr);
            if (u8len <= 0) {
                Botan::secure_scrub_memory(wbuf,
                    static_cast<size_t>(wlen) * sizeof(wchar_t));
                std::free(wbuf);
                LOG_WARN("read_password: WideCharToMultiByte failed (err=%lu); "
                         "non-ASCII passwords may not match browser viewer",
                         GetLastError());
            } else {
                Botan::secure_vector<char> utf8(static_cast<size_t>(u8len));
                WideCharToMultiByte(CP_UTF8, 0, wbuf, wlen,
                                    utf8.data(), u8len,
                                    nullptr, nullptr);
                Botan::secure_scrub_memory(wbuf,
                    static_cast<size_t>(wlen) * sizeof(wchar_t));
                std::free(wbuf);

                // Scrub the original (code-page) bytes and replace with UTF-8.
                Botan::secure_scrub_memory(pw.data(), pw.size());
                pw = std::move(utf8);
            }
        }
    }
#endif // _WIN32

    return pw;
}

} // namespace cli
