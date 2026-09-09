#pragma once

#include "sbom_dsl/lexer/token.hpp"
#include "sbom_dsl/ast/ast.hpp"
#include "sbom_dsl/common/diagnostic.hpp"
#include <vector>
#include <memory>

namespace sbom_dsl {

class Parser {
public:
    Parser(std::vector<Token> tokens, DiagnosticEngine& diag);

    std::unique_ptr<ProgramNode> parse_program();
    std::unique_ptr<StatementNode> parse_statement();

private:
    // Statement parsers
    std::unique_ptr<SelectStatement> parse_select_statement();
    std::unique_ptr<WhoUsesStatement> parse_who_uses_statement();
    std::unique_ptr<FindVulnerableStatement> parse_find_vulnerable_statement();
    std::unique_ptr<ShowTreeStatement> parse_show_tree_statement();
    std::unique_ptr<BlastRadiusStatement> parse_blast_radius_statement();

    // Expression parser (Pratt Precedence Climbing)
    std::unique_ptr<ExpressionNode> parse_expression(int min_precedence = 0);
    std::unique_ptr<ExpressionNode> parse_primary();
    std::vector<std::string> parse_column_path();

    // Helper methods
    bool is_at_end() const;
    const Token& peek() const;
    const Token& previous() const;
    const Token& advance();
    bool check(TokenType type) const;
    bool match(TokenType type);
    const Token& consume(TokenType type, const std::string& message);
    void synchronize();

    int get_infix_precedence(TokenType type) const;
    BinaryOperator token_to_binary_op(TokenType type) const;

    std::vector<Token> tokens_;
    DiagnosticEngine& diag_;
    size_t current_{0};
};

} // namespace sbom_dsl
