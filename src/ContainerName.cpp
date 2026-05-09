#include "ContainerName.h"

namespace scef {

std::string validateContainerName(std::string_view name)
{
    if (name.empty()) {
        return "Container name must not be empty.";
    }
    if (name.find('/') != std::string_view::npos ||
        name.find('\\') != std::string_view::npos) {
        return std::string("--name must be a filename only (no '/' or '\\' separators): ")
               + std::string(name);
    }
    return {};
}

} // namespace scef
