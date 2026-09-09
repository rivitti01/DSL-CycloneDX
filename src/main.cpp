#include "sbom_dsl/cli/cli_options.hpp"
#include "sbom_dsl/lexer/lexer.hpp"
#include "sbom_dsl/parser/parser.hpp"
#include "sbom_dsl/ast/ast_printer.hpp"
#include "sbom_dsl/semantic/type_checker.hpp"
#include "sbom_dsl/lowering/query_lowerer.hpp"
#include "sbom_dsl/ir/ir_printer.hpp"
#include "sbom_dsl/ir/ir_optimizer.hpp"
#include "sbom_dsl/backend/native_engine.hpp"
#include "sbom_dsl/backend/sbom_utility_codegen.hpp"
#include "sbom_dsl/backend/result_formatter.hpp"

#include <iostream>
#include <fstream>
#include <sstream>

using namespace sbom_dsl;

static int execute_query_pipeline(const std::string& source,
                                   const std::string& filename,
                                   const CLIOptions& opts,
                                   NativeEngine& engine) {
    DiagnosticEngine diag;

    // Stage 1: Lexer
    Lexer lexer(source, filename, diag);
    auto tokens = lexer.tokenize();

    if (opts.explain) {
        std::cout << "\n=======================================================\n";
        std::cout << "[PHASE 1] LEXICAL ANALYSIS (TOKENS):\n";
        std::cout << "=======================================================\n";
        for (const auto& tok : tokens) {
            std::cout << "  " << tok.to_string() << "\n";
        }
    }

    if (diag.has_errors()) {
        diag.print_all(std::cerr);
        return 1;
    }

    // Stage 2: Parser
    Parser parser(std::move(tokens), diag);
    auto program = parser.parse_program();

    if (diag.has_errors() || !program) {
        diag.print_all(std::cerr);
        return 1;
    }

    if (opts.explain) {
        std::cout << "\n=======================================================\n";
        std::cout << "[PHASE 2] ABSTRACT SYNTAX TREE (AST):\n";
        std::cout << "=======================================================\n";
        ASTPrinter ast_printer;
        std::cout << ast_printer.print(*program);
    }

    // Stage 3: Semantic Analysis
    TypeChecker checker(diag);
    bool semantic_ok = checker.check(*program);

    if (opts.explain) {
        std::cout << "\n=======================================================\n";
        std::cout << "[PHASE 3] SEMANTIC ANALYSIS & TYPE CHECKING:\n";
        std::cout << "=======================================================\n";
        if (semantic_ok) {
            std::cout << "  Status: PASSED (Schema validated against CycloneDX catalog)\n";
        } else {
            std::cout << "  Status: FAILED (Semantic errors detected)\n";
        }
    }

    if (!semantic_ok || diag.has_errors()) {
        diag.print_all(std::cerr);
        return 1;
    }

    // Stage 4 & 5: Lowering & Execution per statement
    QueryLowerer lowerer;
    bool policy_violation = false;

    for (size_t i = 0; i < program->statements.size(); ++i) {
        auto& stmt = program->statements[i];

        // If a default BOM file was specified via CLI (-b) and statement didn't specify one
        if (opts.bom_file.has_value()) {
            if (auto* sel = dynamic_cast<SelectStatement*>(stmt.get())) {
                if (!sel->bom_path) sel->bom_path = opts.bom_file;
            } else if (auto* who = dynamic_cast<WhoUsesStatement*>(stmt.get())) {
                if (!who->bom_path) who->bom_path = opts.bom_file;
            } else if (auto* find = dynamic_cast<FindVulnerableStatement*>(stmt.get())) {
                if (!find->bom_path) find->bom_path = opts.bom_file;
            } else if (auto* tree = dynamic_cast<ShowTreeStatement*>(stmt.get())) {
                if (!tree->bom_path) tree->bom_path = opts.bom_file;
            } else if (auto* blast = dynamic_cast<BlastRadiusStatement*>(stmt.get())) {
                if (!blast->bom_path) blast->bom_path = opts.bom_file;
            } else if (auto* asrt = dynamic_cast<AssertStatement*>(stmt.get())) {
                if (!asrt->bom_path) asrt->bom_path = opts.bom_file;
            }
        }

        auto plan = lowerer.lower(*stmt);

        IROptimizer optimizer;
        auto optimized_plan = optimizer.optimize(plan);

        if (opts.explain) {
            std::cout << "\n=======================================================\n";
            std::cout << "[PHASE 4] LOWERING TO INTERMEDIATE REPRESENTATION (IR):\n";
            std::cout << "=======================================================\n";
            std::cout << "--- Initial Plan (Unoptimized) ---\n";
            std::cout << IRPrinter::print(plan);

            std::cout << "\n=======================================================\n";
            std::cout << "[PHASE 4.1] IR OPTIMIZATION (ALGEBRAIC OPTIMIZER):\n";
            std::cout << "=======================================================\n";
            std::cout << "Applied Passes: Constant Folding, Predicate Pushdown, Dead Filter Elimination\n";
            std::cout << "--- Optimized Plan ---\n";
            std::cout << IRPrinter::print(optimized_plan);

            std::cout << "\n=======================================================\n";
            std::cout << "[PHASE 5] TARGET CODEGEN (sbom-utility):\n";
            std::cout << "=======================================================\n";
            std::string reason;
            if (SbomUtilityCodeGen::can_offload(optimized_plan, &reason)) {
                auto cmd = SbomUtilityCodeGen::generate_command(optimized_plan, opts.bom_file.value_or("bom.json"));
                std::cout << "  Mappable to sbom-utility CLI: YES\n";
                std::cout << "  Generated Command: " << cmd.value_or("") << "\n";
            } else {
                std::cout << "  Mappable to sbom-utility CLI: NO\n";
                std::cout << "  Reason: " << reason << "\n";
                std::cout << "  Execution Route: Evaluated via Native CycloneDX Graph Engine\n";
            }
            std::cout << "\n=======================================================\n";
            std::cout << "[EXECUTION RESULTS]:\n";
            std::cout << "=======================================================\n";
        }

        // Execution
        QueryResult result;
        if (opts.prefer_sbom_utility && SbomUtilityCodeGen::can_offload(optimized_plan)) {
            auto cmd = SbomUtilityCodeGen::generate_command(optimized_plan, opts.bom_file.value_or("bom.json"));
            if (cmd) {
                result = SbomUtilityCodeGen::execute_command(*cmd, diag);
            }
        }
        
        if (result.is_empty()) {
            // Run on Native Engine
            result = engine.execute(optimized_plan, diag);
        }

        if (result.is_assertion && !result.assertion_passed) {
            policy_violation = true;
        }

        if (diag.has_errors()) {
            diag.print_all(std::cerr);
            return 1;
        } else {
            std::cout << ResultFormatter::format(result, opts.output_format);
        }
    }

    return policy_violation ? 1 : 0;
}

static void run_repl(const CLIOptions& base_opts, NativeEngine& engine) {
    CLIOptions opts = base_opts;
    std::cout << "CycloneDX Query DSL Interactive Shell (REPL)\n"
              << "Type your queries followed by ';' or 'exit'/'quit' to exit.\n"
              << "Commands: ':explain [on|off]', ':bom <file>', ':format [table|json|tree|dot|mermaid]'\n\n";

    std::string line;
    std::string accumulator;

    while (true) {
        if (accumulator.empty()) {
            std::cout << "sbom-dsl> ";
        } else {
            std::cout << "      ...> ";
        }

        if (!std::getline(std::cin, line)) {
            break;
        }

        // Strip whitespace
        size_t start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        std::string trimmed = line.substr(start);

        if (trimmed == "exit" || trimmed == "quit") {
            break;
        }
        if (trimmed == "clear") {
            std::cout << "\033[2J\033[H";
            continue;
        }
        if (trimmed.rfind(":explain", 0) == 0) {
            opts.explain = (trimmed.find("on") != std::string::npos);
            std::cout << "Explain mode: " << (opts.explain ? "ON" : "OFF") << "\n";
            continue;
        }
        if (trimmed.rfind(":bom", 0) == 0) {
            std::string path = trimmed.substr(4);
            size_t p_start = path.find_first_not_of(" \t");
            if (p_start != std::string::npos) {
                opts.bom_file = path.substr(p_start);
                std::cout << "Default SBOM set to: " << *opts.bom_file << "\n";
            }
            continue;
        }
        if (trimmed.rfind(":format", 0) == 0) {
            if (trimmed.find("json") != std::string::npos) opts.output_format = OutputFormat::Json;
            else if (trimmed.find("tree") != std::string::npos) opts.output_format = OutputFormat::Tree;
            else if (trimmed.find("dot") != std::string::npos) opts.output_format = OutputFormat::Dot;
            else if (trimmed.find("mermaid") != std::string::npos) opts.output_format = OutputFormat::Mermaid;
            else opts.output_format = OutputFormat::Table;
            std::cout << "Output format set.\n";
            continue;
        }

        accumulator += line + "\n";
        if (line.find(';') != std::string::npos) {
            execute_query_pipeline(accumulator, "<stdin>", opts, engine);
            accumulator.clear();
        }
    }
}

int main(int argc, char* argv[]) {
    auto opts = CLIOptions::parse(argc, argv);

    if (opts.show_help) {
        CLIOptions::print_help(argv[0]);
        return 0;
    }

    if (opts.show_version) {
        CLIOptions::print_version();
        return 0;
    }

    NativeEngine engine;
    if (opts.bom_file.has_value()) {
        DiagnosticEngine diag;
        engine.load_bom_file(*opts.bom_file, diag);
    }

    if (opts.interactive || (!opts.query_file.has_value() && !opts.inline_query.has_value())) {
        run_repl(opts, engine);
        return 0;
    }

    if (opts.inline_query.has_value()) {
        return execute_query_pipeline(*opts.inline_query, "<command_line>", opts, engine);
    }

    if (opts.query_file.has_value()) {
        std::ifstream file(*opts.query_file);
        if (!file.is_open()) {
            std::cerr << "Error: Could not open query file '" << *opts.query_file << "'\n";
            return 1;
        }
        std::ostringstream ss;
        ss << file.rdbuf();
        return execute_query_pipeline(ss.str(), *opts.query_file, opts, engine);
    }

    return 0;
}
