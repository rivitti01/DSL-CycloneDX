#include "sbom_dsl/cli/cli_options.hpp"
#include <iostream>
#include <cstring>

namespace sbom_dsl {

CLIOptions CLIOptions::parse(int argc, char* argv[]) {
    CLIOptions opts;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            opts.show_help = true;
        } else if (arg == "-v" || arg == "--version") {
            opts.show_version = true;
        } else if (arg == "-e" || arg == "--explain") {
            opts.explain = true;
        } else if (arg == "-i" || arg == "--interactive") {
            opts.interactive = true;
        } else if (arg == "--sbom-utility") {
            opts.prefer_sbom_utility = true;
        } else if (arg == "-c" && i + 1 < argc) {
            opts.inline_query = argv[++i];
        } else if ((arg == "-b" || arg == "--bom") && i + 1 < argc) {
            opts.bom_file = argv[++i];
        } else if ((arg == "-f" || arg == "--format") && i + 1 < argc) {
            std::string fmt = argv[++i];
            if (fmt == "json") opts.output_format = OutputFormat::Json;
            else if (fmt == "tree") opts.output_format = OutputFormat::Tree;
            else opts.output_format = OutputFormat::Table;
        } else if (!arg.empty() && arg[0] != '-') {
            opts.query_file = arg;
        }
    }

    return opts;
}

void CLIOptions::print_help(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [options] [query.dsl]\n\n"
              << "CycloneDX Query DSL Compiler & Execution Engine\n"
              << "Formal Languages and Compilers - Politecnico di Milano\n\n"
              << "Options:\n"
              << "  -c <query>              Execute query inline\n"
              << "  -b, --bom <file>        Specify default CycloneDX SBOM JSON file\n"
              << "  -e, --explain           Explain query execution (tokens, AST, semantic, IR, codegen)\n"
              << "  -f, --format <format>   Output format: table (default), json, tree\n"
              << "  -i, --interactive       Start interactive query shell (REPL)\n"
              << "      --sbom-utility      Attempt offloading to sbom-utility CLI if available\n"
              << "  -h, --help              Show this help message\n"
              << "  -v, --version           Show version information\n\n"
              << "Examples:\n"
              << "  " << prog_name << " -c \"SELECT name, version FROM components;\" -b bom.json\n"
              << "  " << prog_name << " -c \"WHO USES 'log4j-core' TRANSITIVE;\" -b bom.json\n"
              << "  " << prog_name << " -c \"FIND VULNERABLE LIBRARIES SEVERITY >= HIGH;\" -b bom.json\n"
              << "  " << prog_name << " query.dsl --explain\n";
}

void CLIOptions::print_version() {
    std::cout << "CycloneDX Query DSL version 1.0.0 (C++20)\n"
              << "Politecnico di Milano - Formal Languages and Compilers\n";
}

} // namespace sbom_dsl
