#pragma once

#include "sbom_dsl/lexer/token.hpp"
#include "sbom_dsl/common/diagnostic.hpp"
#include <string_view>
#include <vector>

namespace sbom_dsl {

class Lexer {
public:
    Lexer(std::string_view source, std::string filename, DiagnosticEngine& diag);

    std::vector<Token> tokenize();

private:
    char peek() const;
    char peek_next() const;
    char advance();
    bool match(char expected);
    bool is_at_end() const;

    void skip_whitespace_and_comments();
    Token scan_token();
    Token scan_string(char quote_char);
    Token scan_number();
    Token scan_identifier_or_keyword();

    SourceLocation current_location() const;
    std::string current_line_text() const;

    std::string_view source_;
    std::string filename_;
    DiagnosticEngine& diag_;

    size_t cursor_{0};
    size_t line_{1};
    size_t column_{1};
    size_t line_start_{0};
};

} // namespace sbom_dsl
