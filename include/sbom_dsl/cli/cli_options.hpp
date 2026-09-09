#pragma once

#include "sbom_dsl/backend/result_formatter.hpp"
#include <string>
#include <optional>
#include <vector>

namespace sbom_dsl {

struct CLIOptions {
    std::optional<std::string> query_file;
    std::optional<std::string> inline_query;
    std::optional<std::string> bom_file;
    OutputFormat output_format{OutputFormat::Table};
    bool explain{false};
    bool interactive{false};
    bool show_help{false};
    bool show_version{false};
    bool prefer_sbom_utility{false};

    static CLIOptions parse(int argc, char* argv[]);
    static void print_help(const char* prog_name);
    static void print_version();
};

} // namespace sbom_dsl
