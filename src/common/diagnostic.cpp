#include "sbom_dsl/common/diagnostic.hpp"
#include <sstream>

namespace sbom_dsl {

namespace {
    const char* COLOR_RESET   = "\033[0m";
    const char* COLOR_RED     = "\033[1;31m";
    const char* COLOR_YELLOW  = "\033[1;33m";
    const char* COLOR_BLUE    = "\033[1;34m";
    const char* COLOR_BOLD    = "\033[1m";
}

std::string Diagnostic::format(bool colorize) const {
    std::ostringstream oss;
    const char* color = "";
    const char* label = "";

    switch (severity) {
        case DiagnosticSeverity::Error:
            color = COLOR_RED;
            label = "error";
            break;
        case DiagnosticSeverity::Warning:
            color = COLOR_YELLOW;
            label = "warning";
            break;
        case DiagnosticSeverity::Note:
            color = COLOR_BLUE;
            label = "note";
            break;
    }

    if (colorize) {
        oss << COLOR_BOLD << location.to_string() << ": "
            << color << label << ": "
            << COLOR_RESET << COLOR_BOLD << message << COLOR_RESET << "\n";
    } else {
        oss << location.to_string() << ": " << label << ": " << message << "\n";
    }

    if (!source_line.empty()) {
        oss << "    " << source_line << "\n";
        oss << "    ";
        for (size_t i = 1; i < location.column; ++i) {
            oss << ' ';
        }
        if (colorize) {
            oss << color << "^" << COLOR_RESET << "\n";
        } else {
            oss << "^\n";
        }
    }

    return oss.str();
}

void DiagnosticEngine::report(DiagnosticSeverity severity, const SourceLocation& loc, const std::string& msg, const std::string& line) {
    diagnostics_.push_back({severity, loc, msg, line});
    if (severity == DiagnosticSeverity::Error) {
        ++error_count_;
    } else if (severity == DiagnosticSeverity::Warning) {
        ++warning_count_;
    }
}

void DiagnosticEngine::error(const SourceLocation& loc, const std::string& msg, const std::string& line) {
    report(DiagnosticSeverity::Error, loc, msg, line);
}

void DiagnosticEngine::warning(const SourceLocation& loc, const std::string& msg, const std::string& line) {
    report(DiagnosticSeverity::Warning, loc, msg, line);
}

void DiagnosticEngine::note(const SourceLocation& loc, const std::string& msg, const std::string& line) {
    report(DiagnosticSeverity::Note, loc, msg, line);
}

std::string DiagnosticEngine::format_all(bool colorize) const {
    std::ostringstream oss;
    for (const auto& diag : diagnostics_) {
        oss << diag.format(colorize);
    }
    return oss.str();
}

void DiagnosticEngine::print_all(std::ostream& os, bool colorize) const {
    os << format_all(colorize);
}

void DiagnosticEngine::clear() {
    diagnostics_.clear();
    error_count_ = 0;
    warning_count_ = 0;
}

} // namespace sbom_dsl
