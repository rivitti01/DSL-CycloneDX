#pragma once

#include "sbom_dsl/common/source_location.hpp"
#include <string>
#include <vector>
#include <iostream>

namespace sbom_dsl {

enum class DiagnosticSeverity {
    Note,
    Warning,
    Error
};

struct Diagnostic {
    DiagnosticSeverity severity{DiagnosticSeverity::Error};
    SourceLocation location;
    std::string message;
    std::string source_line;

    std::string format(bool colorize = true) const;
};

class DiagnosticEngine {
public:
    void report(DiagnosticSeverity severity, const SourceLocation& loc, const std::string& msg, const std::string& line = "");
    void error(const SourceLocation& loc, const std::string& msg, const std::string& line = "");
    void warning(const SourceLocation& loc, const std::string& msg, const std::string& line = "");
    void note(const SourceLocation& loc, const std::string& msg, const std::string& line = "");

    bool has_errors() const { return error_count_ > 0; }
    size_t error_count() const { return error_count_; }
    size_t warning_count() const { return warning_count_; }

    const std::vector<Diagnostic>& diagnostics() const { return diagnostics_; }
    std::string format_all(bool colorize = true) const;
    void print_all(std::ostream& os = std::cerr, bool colorize = true) const;
    void clear();

private:
    std::vector<Diagnostic> diagnostics_;
    size_t error_count_{0};
    size_t warning_count_{0};
};

} // namespace sbom_dsl
