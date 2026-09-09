#pragma once

#include <string>
#include <cstddef>

namespace sbom_dsl {

struct SourceLocation {
    std::string filename{"<input>"};
    size_t line{1};
    size_t column{1};
    size_t offset{0};

    bool operator==(const SourceLocation& other) const = default;

    std::string to_string() const {
        return filename + ":" + std::to_string(line) + ":" + std::to_string(column);
    }
};

} // namespace sbom_dsl
