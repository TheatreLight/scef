#ifndef CLI_PASSWORD_IO_H
#define CLI_PASSWORD_IO_H

#include <botan/secmem.h>

namespace cli {

// Read a password from stdin (up to the first newline or EOF).
// Disables terminal echo while reading. On Windows, converts the console
// input code-page bytes to UTF-8 so the result matches the browser viewer.
// Throws std::runtime_error if the password is empty.
[[nodiscard]] Botan::secure_vector<char> read_password();

} // namespace cli

#endif // CLI_PASSWORD_IO_H