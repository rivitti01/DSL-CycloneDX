#include "sbom_dsl/lexer/token.hpp"
#include <unordered_map>
#include <algorithm>
#include <cctype>

namespace sbom_dsl {

std::string_view token_type_name(TokenType type) {
    switch (type) {
        case TokenType::EndOfFile: return "EOF";
        case TokenType::Invalid: return "INVALID";
        case TokenType::Identifier: return "IDENTIFIER";
        case TokenType::StringLiteral: return "STRING";
        case TokenType::IntegerLiteral: return "INTEGER";
        case TokenType::FloatLiteral: return "FLOAT";
        case TokenType::BooleanLiteral: return "BOOLEAN";

        case TokenType::KwSelect: return "SELECT";
        case TokenType::KwFrom: return "FROM";
        case TokenType::KwWhere: return "WHERE";
        case TokenType::KwGroup: return "GROUP";
        case TokenType::KwBy: return "BY";
        case TokenType::KwOrder: return "ORDER";
        case TokenType::KwAsc: return "ASC";
        case TokenType::KwDesc: return "DESC";
        case TokenType::KwLimit: return "LIMIT";
        case TokenType::KwIn: return "IN";
        case TokenType::KwCount: return "COUNT";

        case TokenType::KwWho: return "WHO";
        case TokenType::KwUses: return "USES";
        case TokenType::KwTransitive: return "TRANSITIVE";
        case TokenType::KwDirect: return "DIRECT";
        case TokenType::KwFind: return "FIND";
        case TokenType::KwVulnerable: return "VULNERABLE";
        case TokenType::KwComponents: return "COMPONENTS";
        case TokenType::KwLibraries: return "LIBRARIES";
        case TokenType::KwVulnerabilities: return "VULNERABILITIES";
        case TokenType::KwSeverity: return "SEVERITY";
        case TokenType::KwShow: return "SHOW";
        case TokenType::KwTree: return "TREE";
        case TokenType::KwDependencies: return "DEPENDENCIES";
        case TokenType::KwOf: return "OF";
        case TokenType::KwDepth: return "DEPTH";
        case TokenType::KwBlast: return "BLAST";
        case TokenType::KwRadius: return "RADIUS";
        case TokenType::KwAssert: return "ASSERT";
        case TokenType::KwNo: return "NO";

        case TokenType::KwAnd: return "AND";
        case TokenType::KwOr: return "OR";
        case TokenType::KwNot: return "NOT";

        case TokenType::KwContains: return "CONTAINS";
        case TokenType::KwMatches: return "MATCHES";
        case TokenType::KwLike: return "LIKE";

        case TokenType::KwCritical: return "CRITICAL";
        case TokenType::KwHigh: return "HIGH";
        case TokenType::KwMedium: return "MEDIUM";
        case TokenType::KwLow: return "LOW";
        case TokenType::KwInfo: return "INFO";
        case TokenType::KwNone: return "NONE";

        case TokenType::Star: return "*";
        case TokenType::Comma: return ",";
        case TokenType::Dot: return ".";
        case TokenType::Semicolon: return ";";
        case TokenType::LParen: return "(";
        case TokenType::RParen: return ")";

        case TokenType::Equal: return "=";
        case TokenType::NotEqual: return "!=";
        case TokenType::Less: return "<";
        case TokenType::LessEqual: return "<=";
        case TokenType::Greater: return ">";
        case TokenType::GreaterEqual: return ">=";
    }
    return "UNKNOWN";
}

std::optional<TokenType> lookup_keyword(std::string_view text) {
    std::string upper;
    upper.reserve(text.size());
    for (char c : text) {
        upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }

    static const std::unordered_map<std::string, TokenType> keywords = {
        {"SELECT", TokenType::KwSelect},
        {"FROM", TokenType::KwFrom},
        {"WHERE", TokenType::KwWhere},
        {"GROUP", TokenType::KwGroup},
        {"BY", TokenType::KwBy},
        {"ORDER", TokenType::KwOrder},
        {"ASC", TokenType::KwAsc},
        {"DESC", TokenType::KwDesc},
        {"LIMIT", TokenType::KwLimit},
        {"IN", TokenType::KwIn},
        {"COUNT", TokenType::KwCount},

        {"WHO", TokenType::KwWho},
        {"USES", TokenType::KwUses},
        {"TRANSITIVE", TokenType::KwTransitive},
        {"DIRECT", TokenType::KwDirect},
        {"FIND", TokenType::KwFind},
        {"VULNERABLE", TokenType::KwVulnerable},
        {"COMPONENTS", TokenType::KwComponents},
        {"LIBRARIES", TokenType::KwLibraries},
        {"VULNERABILITIES", TokenType::KwVulnerabilities},
        {"SEVERITY", TokenType::KwSeverity},
        {"SHOW", TokenType::KwShow},
        {"TREE", TokenType::KwTree},
        {"DEPENDENCIES", TokenType::KwDependencies},
        {"OF", TokenType::KwOf},
        {"DEPTH", TokenType::KwDepth},
        {"BLAST", TokenType::KwBlast},
        {"RADIUS", TokenType::KwRadius},
        {"ASSERT", TokenType::KwAssert},
        {"NO", TokenType::KwNo},

        {"AND", TokenType::KwAnd},
        {"OR", TokenType::KwOr},
        {"NOT", TokenType::KwNot},

        {"CONTAINS", TokenType::KwContains},
        {"MATCHES", TokenType::KwMatches},
        {"LIKE", TokenType::KwLike},

        {"CRITICAL", TokenType::KwCritical},
        {"HIGH", TokenType::KwHigh},
        {"MEDIUM", TokenType::KwMedium},
        {"LOW", TokenType::KwLow},
        {"INFO", TokenType::KwInfo},
        {"NONE", TokenType::KwNone},

        {"TRUE", TokenType::BooleanLiteral},
        {"FALSE", TokenType::BooleanLiteral}
    };

    auto it = keywords.find(upper);
    if (it != keywords.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::string Token::to_string() const {
    return std::string(token_type_name(type)) + "('" + lexeme + "') at " + location.to_string();
}

bool Token::is_keyword() const {
    return static_cast<int>(type) >= static_cast<int>(TokenType::KwSelect) &&
           static_cast<int>(type) <= static_cast<int>(TokenType::KwNone);
}

bool Token::is_literal() const {
    return type == TokenType::StringLiteral ||
           type == TokenType::IntegerLiteral ||
           type == TokenType::FloatLiteral ||
           type == TokenType::BooleanLiteral;
}

bool Token::is_comparison_op() const {
    return type == TokenType::Equal ||
           type == TokenType::NotEqual ||
           type == TokenType::Less ||
           type == TokenType::LessEqual ||
           type == TokenType::Greater ||
           type == TokenType::GreaterEqual ||
           type == TokenType::KwContains ||
           type == TokenType::KwMatches ||
           type == TokenType::KwLike;
}

} // namespace sbom_dsl
