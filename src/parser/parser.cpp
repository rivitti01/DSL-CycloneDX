#include "sbom_dsl/parser/parser.hpp"
#include <stdexcept>

namespace sbom_dsl {

namespace {
    enum Precedence {
        PrecNone = 0,
        PrecOr = 1,
        PrecAnd = 2,
        PrecContains = 3,
        PrecComparison = 4,
        PrecPrimary = 5
    };
}

Parser::Parser(std::vector<Token> tokens, DiagnosticEngine& diag)
    : tokens_(std::move(tokens)), diag_(diag) {}

bool Parser::is_at_end() const {
    return peek().type == TokenType::EndOfFile;
}

const Token& Parser::peek() const {
    return tokens_[current_];
}

const Token& Parser::previous() const {
    return tokens_[current_ - 1];
}

const Token& Parser::advance() {
    if (!is_at_end()) {
        ++current_;
    }
    return previous();
}

bool Parser::check(TokenType type) const {
    if (is_at_end()) return false;
    return peek().type == type;
}

bool Parser::match(TokenType type) {
    if (check(type)) {
        advance();
        return true;
    }
    return false;
}

const Token& Parser::consume(TokenType type, const std::string& message) {
    if (check(type)) {
        return advance();
    }
    diag_.error(peek().location, message);
    throw std::runtime_error(message);
}

void Parser::synchronize() {
    advance();
    while (!is_at_end()) {
        if (previous().type == TokenType::Semicolon) return;
        switch (peek().type) {
            case TokenType::KwSelect:
            case TokenType::KwWho:
            case TokenType::KwFind:
            case TokenType::KwShow:
            case TokenType::KwAssert:
                return;
            default:
                advance();
        }
    }
}

int Parser::get_infix_precedence(TokenType type) const {
    switch (type) {
        case TokenType::KwOr:
            return PrecOr;
        case TokenType::KwAnd:
            return PrecAnd;
        case TokenType::KwContains:
        case TokenType::KwMatches:
        case TokenType::KwLike:
        case TokenType::Equal:
        case TokenType::NotEqual:
        case TokenType::Less:
        case TokenType::LessEqual:
        case TokenType::Greater:
        case TokenType::GreaterEqual:
            return PrecComparison;
        default:
            return PrecNone;
    }
}

BinaryOperator Parser::token_to_binary_op(TokenType type) const {
    switch (type) {
        case TokenType::KwOr: return BinaryOperator::Or;
        case TokenType::KwAnd: return BinaryOperator::And;
        case TokenType::KwContains: return BinaryOperator::Contains;
        case TokenType::KwMatches: return BinaryOperator::Matches;
        case TokenType::KwLike: return BinaryOperator::Like;
        case TokenType::Equal: return BinaryOperator::Equal;
        case TokenType::NotEqual: return BinaryOperator::NotEqual;
        case TokenType::Less: return BinaryOperator::Less;
        case TokenType::LessEqual: return BinaryOperator::LessEqual;
        case TokenType::Greater: return BinaryOperator::Greater;
        case TokenType::GreaterEqual: return BinaryOperator::GreaterEqual;
        default:
            throw std::runtime_error("Unexpected token type for binary operator");
    }
}

std::vector<std::string> Parser::parse_column_path() {
    std::vector<std::string> path;
    const Token& first = advance();
    path.push_back(first.lexeme);

    while (match(TokenType::Dot)) {
        if (check(TokenType::Identifier) || peek().is_keyword()) {
            path.push_back(advance().lexeme);
        } else {
            diag_.error(peek().location, "Expected identifier after '.' in column path");
            break;
        }
    }
    return path;
}

std::unique_ptr<ExpressionNode> Parser::parse_primary() {
    const Token& tok = peek();

    // Parenthesized expression: ( expr )
    if (match(TokenType::LParen)) {
        auto expr = parse_expression(PrecNone);
        consume(TokenType::RParen, "Expected ')' after expression");
        return expr;
    }

    // Unary operator NOT: NOT expr
    if (match(TokenType::KwNot)) {
        SourceLocation loc = previous().location;
        auto operand = parse_expression(PrecComparison);
        return std::make_unique<UnaryOpExpr>(UnaryOperator::Not, std::move(operand), loc);
    }

    // String literal
    if (match(TokenType::StringLiteral)) {
        return std::make_unique<LiteralExpr>(previous().lexeme, previous().location);
    }

    // Integer literal
    if (match(TokenType::IntegerLiteral)) {
        int64_t val = std::stoll(previous().lexeme);
        return std::make_unique<LiteralExpr>(val, previous().location);
    }

    // Float literal
    if (match(TokenType::FloatLiteral)) {
        double val = std::stod(previous().lexeme);
        return std::make_unique<LiteralExpr>(val, previous().location);
    }

    // Boolean literal
    if (match(TokenType::BooleanLiteral)) {
        bool val = (previous().lexeme == "true" || previous().lexeme == "TRUE");
        return std::make_unique<LiteralExpr>(val, previous().location);
    }

    // Severity level literal (CRITICAL, HIGH, etc.)
    auto sev = severity_from_string(tok.lexeme);
    if (sev.has_value() && (tok.type == TokenType::KwCritical || tok.type == TokenType::KwHigh ||
                            tok.type == TokenType::KwMedium || tok.type == TokenType::KwLow ||
                            tok.type == TokenType::KwInfo || tok.type == TokenType::KwNone)) {
        advance();
        return std::make_unique<LiteralExpr>(*sev, previous().location);
    }

    // Column reference or Identifier
    if (tok.type == TokenType::Identifier || tok.is_keyword()) {
        SourceLocation loc = tok.location;
        auto path = parse_column_path();
        return std::make_unique<ColumnRefExpr>(std::move(path), loc);
    }

    diag_.error(tok.location, "Unexpected token in expression: '" + tok.lexeme + "'");
    advance();
    return nullptr;
}

std::unique_ptr<ExpressionNode> Parser::parse_expression(int min_precedence) {
    auto left = parse_primary();
    if (!left) return nullptr;

    while (!is_at_end()) {
        int prec = get_infix_precedence(peek().type);
        if (prec == PrecNone || prec < min_precedence) {
            break;
        }

        const Token& op_token = advance();
        BinaryOperator op = token_to_binary_op(op_token.type);

        // Precedence climbing (left-associative)
        auto right = parse_expression(prec + 1);
        if (!right) {
            diag_.error(op_token.location, "Expected expression after operator '" + op_token.lexeme + "'");
            return nullptr;
        }

        left = std::make_unique<BinaryOpExpr>(op, std::move(left), std::move(right), op_token.location);
    }

    return left;
}

std::unique_ptr<SelectStatement> Parser::parse_select_statement() {
    SourceLocation loc = previous().location; // KwSelect location
    auto stmt = std::make_unique<SelectStatement>(loc);

    // Projections: '*' or list of columns
    if (match(TokenType::Star)) {
        // empty projections vector signifies '*'
    } else {
        do {
            auto path = parse_column_path();
            std::string full;
            for (size_t i = 0; i < path.size(); ++i) {
                if (i > 0) full += ".";
                full += path[i];
            }
            stmt->projections.push_back(full);
        } while (match(TokenType::Comma));
    }

    // FROM collection
    consume(TokenType::KwFrom, "Expected 'FROM' in SELECT statement");

    auto collection_path = parse_column_path();
    std::string coll_name;
    for (size_t i = 0; i < collection_path.size(); ++i) {
        if (i > 0) coll_name += ".";
        coll_name += collection_path[i];
    }
    stmt->collection = coll_name;

    // Optional IN "bom.json"
    if (match(TokenType::KwIn)) {
        const Token& file_tok = consume(TokenType::StringLiteral, "Expected string literal for file path after 'IN'");
        stmt->bom_path = file_tok.lexeme;
    }

    // Optional WHERE clause
    if (match(TokenType::KwWhere)) {
        stmt->where_clause = parse_expression(PrecNone);
    }

    // Optional IN "bom.json" after WHERE
    if (!stmt->bom_path && match(TokenType::KwIn)) {
        const Token& file_tok = consume(TokenType::StringLiteral, "Expected string literal for file path after 'IN'");
        stmt->bom_path = file_tok.lexeme;
    }

    // Optional ORDER BY
    if (match(TokenType::KwOrder)) {
        consume(TokenType::KwBy, "Expected 'BY' after 'ORDER'");
        auto order_col_path = parse_column_path();
        std::string order_col;
        for (size_t i = 0; i < order_col_path.size(); ++i) {
            if (i > 0) order_col += ".";
            order_col += order_col_path[i];
        }
        bool asc = true;
        if (match(TokenType::KwDesc)) {
            asc = false;
        } else {
            match(TokenType::KwAsc); // optional ASC
        }
        stmt->order_by = OrderByClause{order_col, asc};
    }

    // Optional LIMIT
    if (match(TokenType::KwLimit)) {
        const Token& limit_tok = consume(TokenType::IntegerLiteral, "Expected integer literal after 'LIMIT'");
        stmt->limit = static_cast<size_t>(std::stoll(limit_tok.lexeme));
    }

    // Optional IN "bom.json" at the end
    if (!stmt->bom_path && match(TokenType::KwIn)) {
        const Token& file_tok = consume(TokenType::StringLiteral, "Expected string literal for file path after 'IN'");
        stmt->bom_path = file_tok.lexeme;
    }

    // Optional semicolon
    match(TokenType::Semicolon);

    return stmt;
}

std::unique_ptr<WhoUsesStatement> Parser::parse_who_uses_statement() {
    SourceLocation loc = previous().location; // KwWho
    consume(TokenType::KwUses, "Expected 'USES' after 'WHO'");

    std::string target;
    if (match(TokenType::StringLiteral) || match(TokenType::Identifier)) {
        target = previous().lexeme;
    } else {
        diag_.error(peek().location, "Expected target component name or string after 'WHO USES'");
        return nullptr;
    }

    bool transitive = true;
    if (match(TokenType::KwDirect)) {
        transitive = false;
    } else {
        match(TokenType::KwTransitive);
    }

    auto stmt = std::make_unique<WhoUsesStatement>(target, transitive, loc);

    if (match(TokenType::KwIn)) {
        const Token& file_tok = consume(TokenType::StringLiteral, "Expected string literal for file path after 'IN'");
        stmt->bom_path = file_tok.lexeme;
    }

    match(TokenType::Semicolon);
    return stmt;
}

std::unique_ptr<FindVulnerableStatement> Parser::parse_find_vulnerable_statement() {
    SourceLocation loc = previous().location; // KwFind
    consume(TokenType::KwVulnerable, "Expected 'VULNERABLE' after 'FIND'");

    bool libraries_only = false;
    if (match(TokenType::KwLibraries)) {
        libraries_only = true;
    } else if (match(TokenType::KwComponents)) {
        libraries_only = false;
    } else {
        diag_.error(peek().location, "Expected 'COMPONENTS' or 'LIBRARIES' after 'FIND VULNERABLE'");
        return nullptr;
    }

    auto stmt = std::make_unique<FindVulnerableStatement>(libraries_only, loc);

    // Optional SEVERITY [op] LEVEL
    if (match(TokenType::KwSeverity)) {
        BinaryOperator op = BinaryOperator::Equal;
        if (peek().is_comparison_op()) {
            op = token_to_binary_op(advance().type);
        }

        const Token& sev_tok = advance();
        auto sev = severity_from_string(sev_tok.lexeme);
        if (!sev.has_value()) {
            diag_.error(sev_tok.location, "Expected severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO, NONE)");
            return nullptr;
        }
        stmt->severity_op = op;
        stmt->severity_level = *sev;
    }

    // Optional WHERE
    if (match(TokenType::KwWhere)) {
        stmt->where_clause = parse_expression(PrecNone);
    }

    // Optional IN "bom.json"
    if (match(TokenType::KwIn)) {
        const Token& file_tok = consume(TokenType::StringLiteral, "Expected string literal for file path after 'IN'");
        stmt->bom_path = file_tok.lexeme;
    }

    match(TokenType::Semicolon);
    return stmt;
}

std::unique_ptr<ShowTreeStatement> Parser::parse_show_tree_statement() {
    SourceLocation loc = previous().location; // KwShow
    if (!match(TokenType::KwTree) && !match(TokenType::KwDependencies)) {
        diag_.error(peek().location, "Expected 'TREE' or 'DEPENDENCIES' after 'SHOW'");
        return nullptr;
    }

    auto stmt = std::make_unique<ShowTreeStatement>(loc);

    // Optional OF "component"
    if (match(TokenType::KwOf)) {
        if (match(TokenType::StringLiteral) || match(TokenType::Identifier)) {
            stmt->root_component = previous().lexeme;
        } else {
            diag_.error(peek().location, "Expected component name after 'OF'");
            return nullptr;
        }
    }

    // Optional DEPTH n
    if (match(TokenType::KwDepth)) {
        const Token& depth_tok = consume(TokenType::IntegerLiteral, "Expected integer literal after 'DEPTH'");
        stmt->max_depth = static_cast<size_t>(std::stoll(depth_tok.lexeme));
    }

    // Optional IN "bom.json"
    if (match(TokenType::KwIn)) {
        const Token& file_tok = consume(TokenType::StringLiteral, "Expected string literal for file path after 'IN'");
        stmt->bom_path = file_tok.lexeme;
    }

    match(TokenType::Semicolon);
    return stmt;
}

std::unique_ptr<BlastRadiusStatement> Parser::parse_blast_radius_statement() {
    SourceLocation loc = previous().location; // KwFind
    consume(TokenType::KwBlast, "Expected 'BLAST' after 'FIND'");
    consume(TokenType::KwRadius, "Expected 'RADIUS' after 'BLAST'");
    consume(TokenType::KwOf, "Expected 'OF' after 'BLAST RADIUS'");

    std::string vuln_id;
    if (match(TokenType::StringLiteral) || match(TokenType::Identifier)) {
        vuln_id = previous().lexeme;
    } else {
        diag_.error(peek().location, "Expected vulnerability ID (e.g. 'CVE-2021-44228') after 'OF'");
        return nullptr;
    }

    auto stmt = std::make_unique<BlastRadiusStatement>(vuln_id, loc);

    if (match(TokenType::KwIn)) {
        const Token& file_tok = consume(TokenType::StringLiteral, "Expected string literal for file path after 'IN'");
        stmt->bom_path = file_tok.lexeme;
    }

    match(TokenType::Semicolon);
    return stmt;
}

std::unique_ptr<AssertStatement> Parser::parse_assert_statement() {
    SourceLocation loc = previous().location; // KwAssert
    if (!match(TokenType::KwNo)) {
        diag_.error(peek().location, "Expected 'NO' after 'ASSERT'");
        return nullptr;
    }

    AssertTarget target;
    if (match(TokenType::KwVulnerabilities)) {
        target = AssertTarget::Vulnerabilities;
    } else if (match(TokenType::KwComponents)) {
        target = AssertTarget::Components;
    } else if (match(TokenType::KwLibraries)) {
        target = AssertTarget::Libraries;
    } else {
        diag_.error(peek().location, "Expected 'VULNERABILITIES', 'COMPONENTS', or 'LIBRARIES' after 'ASSERT NO'");
        return nullptr;
    }

    auto stmt = std::make_unique<AssertStatement>(target, loc);

    // Optional IN "bom.json"
    if (match(TokenType::KwIn)) {
        const Token& file_tok = consume(TokenType::StringLiteral, "Expected string literal for file path after 'IN'");
        stmt->bom_path = file_tok.lexeme;
    }

    // Optional SEVERITY [op] (LEVEL | number)
    if (match(TokenType::KwSeverity)) {
        BinaryOperator op = BinaryOperator::Equal;
        if (peek().is_comparison_op()) {
            op = token_to_binary_op(advance().type);
        }

        const Token& sev_tok = advance();
        auto sev = severity_from_string(sev_tok.lexeme);
        if (sev.has_value()) {
            stmt->severity_op = op;
            stmt->severity_level = *sev;
        } else if (sev_tok.type == TokenType::FloatLiteral || sev_tok.type == TokenType::IntegerLiteral) {
            stmt->severity_op = op;
            stmt->score_threshold = std::stod(sev_tok.lexeme);
        } else {
            diag_.error(sev_tok.location, "Expected severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO, NONE) or numeric score after 'SEVERITY'");
            return nullptr;
        }
    }

    // Optional WHERE clause
    if (match(TokenType::KwWhere)) {
        stmt->where_clause = parse_expression(PrecNone);
    }

    // Optional IN "bom.json" after WHERE / SEVERITY
    if (!stmt->bom_path && match(TokenType::KwIn)) {
        const Token& file_tok = consume(TokenType::StringLiteral, "Expected string literal for file path after 'IN'");
        stmt->bom_path = file_tok.lexeme;
    }

    match(TokenType::Semicolon);
    return stmt;
}

std::unique_ptr<StatementNode> Parser::parse_statement() {
    try {
        if (match(TokenType::KwSelect)) {
            return parse_select_statement();
        }
        if (match(TokenType::KwWho)) {
            return parse_who_uses_statement();
        }
        if (match(TokenType::KwFind)) {
            if (check(TokenType::KwVulnerable)) {
                return parse_find_vulnerable_statement();
            }
            if (check(TokenType::KwBlast)) {
                return parse_blast_radius_statement();
            }
            diag_.error(peek().location, "Expected 'VULNERABLE' or 'BLAST' after 'FIND'");
            return nullptr;
        }
        if (match(TokenType::KwShow)) {
            return parse_show_tree_statement();
        }
        if (match(TokenType::KwAssert)) {
            return parse_assert_statement();
        }

        diag_.error(peek().location, "Expected statement (SELECT, WHO USES, FIND, SHOW, ASSERT)");
        advance();
        return nullptr;
    } catch (const std::exception&) {
        synchronize();
        return nullptr;
    }
}

std::unique_ptr<ProgramNode> Parser::parse_program() {
    auto program = std::make_unique<ProgramNode>(peek().location);

    while (!is_at_end()) {
        auto stmt = parse_statement();
        if (stmt) {
            program->statements.push_back(std::move(stmt));
        } else {
            synchronize();
        }
    }

    return program;
}

} // namespace sbom_dsl
