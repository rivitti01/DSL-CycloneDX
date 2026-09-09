#pragma once

#include "sbom_dsl/common/source_location.hpp"
#include <string>
#include <string_view>

namespace sbom_dsl {

enum class TokenType {
    // Special
    EndOfFile,
    Invalid,

    // Literals & Identifiers
    Identifier,
    StringLiteral,
    IntegerLiteral,
    FloatLiteral,
    BooleanLiteral,

    // SQL-like Keywords
    KwSelect,
    KwFrom,
    KwWhere,
    KwGroup,
    KwBy,
    KwOrder,
    KwAsc,
    KwDesc,
    KwLimit,
    KwIn,
    KwCount,

    // Security & Domain Keywords
    KwWho,
    KwUses,
    KwTransitive,
    KwDirect,
    KwFind,
    KwVulnerable,
    KwComponents,
    KwLibraries,
    KwVulnerabilities,
    KwSeverity,
    KwShow,
    KwTree,
    KwDependencies,
    KwOf,
    KwDepth,
    KwBlast,
    KwRadius,
    KwAssert,
    KwNo,

    // Logical Operators
    KwAnd,
    KwOr,
    KwNot,

    // Comparison Keywords
    KwContains,
    KwMatches,
    KwLike,

    // Severity Levels
    KwCritical,
    KwHigh,
    KwMedium,
    KwLow,
    KwInfo,
    KwNone,

    // Symbols & Delimiters
    Star,          // *
    Comma,         // ,
    Dot,           // .
    Semicolon,     // ;
    LParen,        // (
    RParen,        // )

    // Relational Operators
    Equal,         // =
    NotEqual,      // !=
    Less,          // <
    LessEqual,     // <=
    Greater,       // >
    GreaterEqual   // >=
};

struct Token {
    TokenType type{TokenType::Invalid};
    std::string lexeme;
    SourceLocation location;

    std::string to_string() const;
    bool is(TokenType t) const { return type == t; }
    bool is_keyword() const;
    bool is_literal() const;
    bool is_comparison_op() const;
};

std::string_view token_type_name(TokenType type);
std::optional<TokenType> lookup_keyword(std::string_view text);

} // namespace sbom_dsl
