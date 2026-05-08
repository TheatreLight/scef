#pragma once

#include <string>
#include <string_view>

namespace scef {

// Returns empty string on success. On failure, returns a human-readable
// error message describing why the name is invalid.
// Rejects: empty name, names containing '/' or '\'.
[[nodiscard]] std::string validateContainerName(std::string_view name);

} // namespace scef
