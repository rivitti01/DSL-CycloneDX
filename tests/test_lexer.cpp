#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "sbom_dsl/lexer/lexer.hpp"

using namespace sbom_dsl;

TEST_CASE("Lexer: SQL-like keywords and identifiers") {
    DiagnosticEngine diag;
    std::string source = "SELECT name, version FROM components WHERE type = 'library';";
    Lexer lexer(source, "test.dsl", diag);
    auto tokens = lexer.tokenize();

    CHECK_FALSE(diag.has_errors());
    REQUIRE(tokens.size() == 12);

    CHECK(tokens[0].type == TokenType::KwSelect);
    CHECK(tokens[1].type == TokenType::Identifier);
    CHECK(tokens[1].lexeme == "name");
    CHECK(tokens[2].type == TokenType::Comma);
    CHECK(tokens[3].type == TokenType::Identifier);
    CHECK(tokens[3].lexeme == "version");
    CHECK(tokens[4].type == TokenType::KwFrom);
    CHECK(tokens[5].type == TokenType::KwComponents);
    CHECK(tokens[5].lexeme == "components");
    CHECK(tokens[6].type == TokenType::KwWhere);
    CHECK(tokens[7].type == TokenType::Identifier);
    CHECK(tokens[7].lexeme == "type");
    CHECK(tokens[8].type == TokenType::Equal);
    CHECK(tokens[9].type == TokenType::StringLiteral);
    CHECK(tokens[9].lexeme == "library");
    CHECK(tokens[10].type == TokenType::Semicolon);
    CHECK(tokens[11].type == TokenType::EndOfFile);
}

TEST_CASE("Lexer: Case insensitivity of keywords") {
    DiagnosticEngine diag;
    std::string source = "select * from vulnerabilities where cvss-severity >= HIGH;";
    Lexer lexer(source, "test.dsl", diag);
    auto tokens = lexer.tokenize();

    CHECK_FALSE(diag.has_errors());
    CHECK(tokens[0].type == TokenType::KwSelect);
    CHECK(tokens[1].type == TokenType::Star);
    CHECK(tokens[2].type == TokenType::KwFrom);
    CHECK(tokens[3].type == TokenType::KwVulnerabilities);
    CHECK(tokens[3].lexeme == "vulnerabilities");
    CHECK(tokens[4].type == TokenType::KwWhere);
    CHECK(tokens[5].type == TokenType::Identifier);
    CHECK(tokens[5].lexeme == "cvss-severity");
    CHECK(tokens[6].type == TokenType::GreaterEqual);
    CHECK(tokens[7].type == TokenType::KwHigh);
    CHECK(tokens[8].type == TokenType::Semicolon);
}

TEST_CASE("Lexer: Advanced Domain Keywords") {
    DiagnosticEngine diag;
    std::string source = "WHO USES \"log4j\" TRANSITIVE IN \"bom.json\";";
    Lexer lexer(source, "test.dsl", diag);
    auto tokens = lexer.tokenize();

    CHECK_FALSE(diag.has_errors());
    REQUIRE(tokens.size() == 8);
    CHECK(tokens[0].type == TokenType::KwWho);
    CHECK(tokens[1].type == TokenType::KwUses);
    CHECK(tokens[2].type == TokenType::StringLiteral);
    CHECK(tokens[2].lexeme == "log4j");
    CHECK(tokens[3].type == TokenType::KwTransitive);
    CHECK(tokens[4].type == TokenType::KwIn);
    CHECK(tokens[5].type == TokenType::StringLiteral);
    CHECK(tokens[5].lexeme == "bom.json");
    CHECK(tokens[6].type == TokenType::Semicolon);
    CHECK(tokens[7].type == TokenType::EndOfFile);
}

TEST_CASE("Lexer: Numbers and Booleans") {
    DiagnosticEngine diag;
    std::string source = "LIMIT 10 WHERE score >= 7.5 AND active = true";
    Lexer lexer(source, "test.dsl", diag);
    auto tokens = lexer.tokenize();

    CHECK_FALSE(diag.has_errors());
    CHECK(tokens[0].type == TokenType::KwLimit);
    CHECK(tokens[1].type == TokenType::IntegerLiteral);
    CHECK(tokens[1].lexeme == "10");
    CHECK(tokens[2].type == TokenType::KwWhere);
    CHECK(tokens[3].type == TokenType::Identifier);
    CHECK(tokens[4].type == TokenType::GreaterEqual);
    CHECK(tokens[5].type == TokenType::FloatLiteral);
    CHECK(tokens[5].lexeme == "7.5");
    CHECK(tokens[6].type == TokenType::KwAnd);
    CHECK(tokens[7].type == TokenType::Identifier);
    CHECK(tokens[8].type == TokenType::Equal);
    CHECK(tokens[9].type == TokenType::BooleanLiteral);
}

TEST_CASE("Lexer: Comments handling") {
    DiagnosticEngine diag;
    std::string source = 
        "-- SQL single-line comment\n"
        "SHOW TREE // C++ single-line comment\n"
        "/* multi-line\n"
        "   block comment */\n"
        "OF \"root-app\";";
    Lexer lexer(source, "test.dsl", diag);
    auto tokens = lexer.tokenize();

    CHECK_FALSE(diag.has_errors());
    REQUIRE(tokens.size() == 6);
    CHECK(tokens[0].type == TokenType::KwShow);
    CHECK(tokens[1].type == TokenType::KwTree);
    CHECK(tokens[2].type == TokenType::KwOf);
    CHECK(tokens[3].type == TokenType::StringLiteral);
    CHECK(tokens[3].lexeme == "root-app");
    CHECK(tokens[4].type == TokenType::Semicolon);
    CHECK(tokens[5].type == TokenType::EndOfFile);
}

TEST_CASE("Lexer: Lexical errors") {
    SUBCASE("Unterminated string") {
        DiagnosticEngine diag;
        std::string source = "SELECT 'unterminated";
        Lexer lexer(source, "err.dsl", diag);
        auto tokens = lexer.tokenize();
        CHECK(diag.has_errors());
        CHECK(diag.error_count() == 1);
    }

    SUBCASE("Unterminated block comment") {
        DiagnosticEngine diag;
        std::string source = "/* unclosed comment";
        Lexer lexer(source, "err.dsl", diag);
        auto tokens = lexer.tokenize();
        CHECK(diag.has_errors());
        CHECK(diag.error_count() == 1);
    }

    SUBCASE("Unexpected character") {
        DiagnosticEngine diag;
        std::string source = "SELECT @ from components;";
        Lexer lexer(source, "err.dsl", diag);
        auto tokens = lexer.tokenize();
        CHECK(diag.has_errors());
        CHECK(diag.error_count() == 1);
    }
}

TEST_CASE("Lexer: Pattern matching keywords (LIKE, CONTAINS, MATCHES)") {
    DiagnosticEngine diag;
    std::string source = "LIKE like Like CONTAINS contains Contains MATCHES matches Matches";
    Lexer lexer(source, "test.dsl", diag);
    auto tokens = lexer.tokenize();

    CHECK_FALSE(diag.has_errors());
    REQUIRE(tokens.size() == 10); // 9 keywords + EOF

    CHECK(tokens[0].type == TokenType::KwLike);
    CHECK(tokens[1].type == TokenType::KwLike);
    CHECK(tokens[2].type == TokenType::KwLike);
    CHECK(tokens[3].type == TokenType::KwContains);
    CHECK(tokens[4].type == TokenType::KwContains);
    CHECK(tokens[5].type == TokenType::KwContains);
    CHECK(tokens[6].type == TokenType::KwMatches);
    CHECK(tokens[7].type == TokenType::KwMatches);
    CHECK(tokens[8].type == TokenType::KwMatches);
    CHECK(tokens[9].type == TokenType::EndOfFile);

    for (size_t i = 0; i < 9; ++i) {
        CHECK(tokens[i].is_comparison_op());
        CHECK(tokens[i].is_keyword());
    }
}

TEST_CASE("Lexer: Policy assertion keywords (ASSERT, NO, VULNERABILITIES)") {
    DiagnosticEngine diag;
    std::string source = "ASSERT NO VULNERABILITIES SEVERITY >= CRITICAL;";
    Lexer lexer(source, "test.dsl", diag);
    auto tokens = lexer.tokenize();

    CHECK_FALSE(diag.has_errors());
    REQUIRE(tokens.size() == 8);
    CHECK(tokens[0].type == TokenType::KwAssert);
    CHECK(tokens[0].lexeme == "ASSERT");
    CHECK(tokens[1].type == TokenType::KwNo);
    CHECK(tokens[1].lexeme == "NO");
    CHECK(tokens[2].type == TokenType::KwVulnerabilities);
    CHECK(tokens[2].lexeme == "VULNERABILITIES");
    CHECK(tokens[3].type == TokenType::KwSeverity);
    CHECK(tokens[4].type == TokenType::GreaterEqual);
    CHECK(tokens[5].type == TokenType::KwCritical);
    CHECK(tokens[6].type == TokenType::Semicolon);
    CHECK(tokens[7].type == TokenType::EndOfFile);

    std::string source2 = "assert no components where type = 'framework';";
    Lexer lexer2(source2, "test.dsl", diag);
    auto tokens2 = lexer2.tokenize();
    CHECK_FALSE(diag.has_errors());
    CHECK(tokens2[0].type == TokenType::KwAssert);
    CHECK(tokens2[1].type == TokenType::KwNo);
    CHECK(tokens2[2].type == TokenType::KwComponents);
}

