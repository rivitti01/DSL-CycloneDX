#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "sbom_dsl/lexer/lexer.hpp"
#include "sbom_dsl/parser/parser.hpp"
#include "sbom_dsl/semantic/type_checker.hpp"

using namespace sbom_dsl;

static bool check_semantic(const std::string& query, DiagnosticEngine& diag) {
    Lexer lexer(query, "test.dsl", diag);
    auto tokens = lexer.tokenize();
    Parser parser(std::move(tokens), diag);
    auto prog = parser.parse_program();
    if (diag.has_errors() || !prog) return false;

    TypeChecker checker(diag);
    return checker.check(*prog);
}

TEST_CASE("Semantic Analysis: Valid statements") {
    SUBCASE("Valid select components") {
        DiagnosticEngine diag;
        CHECK(check_semantic("SELECT name, version, type FROM components WHERE type = 'library';", diag));
        CHECK_FALSE(diag.has_errors());
    }

    SUBCASE("Valid select vulnerabilities with score") {
        DiagnosticEngine diag;
        CHECK(check_semantic("SELECT id, cvss-severity FROM vulnerabilities WHERE score >= 7.5;", diag));
        CHECK_FALSE(diag.has_errors());
    }

    SUBCASE("Valid WHO USES") {
        DiagnosticEngine diag;
        CHECK(check_semantic("WHO USES 'lodash' TRANSITIVE IN 'bom.json';", diag));
        CHECK_FALSE(diag.has_errors());
    }

    SUBCASE("Valid FIND VULNERABLE") {
        DiagnosticEngine diag;
        CHECK(check_semantic("FIND VULNERABLE LIBRARIES SEVERITY >= HIGH WHERE cwe = 502;", diag));
        CHECK_FALSE(diag.has_errors());
    }

    SUBCASE("Valid SHOW TREE") {
        DiagnosticEngine diag;
        CHECK(check_semantic("SHOW TREE OF 'juice-shop' DEPTH 4;", diag));
        CHECK_FALSE(diag.has_errors());
    }
}

TEST_CASE("Semantic Analysis: Semantic Errors") {
    SUBCASE("Invalid collection name") {
        DiagnosticEngine diag;
        bool ok = check_semantic("SELECT * FROM invalid_collection;", diag);
        CHECK_FALSE(ok);
        CHECK(diag.has_errors());
    }

    SUBCASE("Type mismatch in comparison") {
        DiagnosticEngine diag;
        // 'name' is String in components, comparing with integer 10 via '<' is invalid!
        bool ok = check_semantic("SELECT * FROM components WHERE name < 10;", diag);
        CHECK_FALSE(ok);
        CHECK(diag.has_errors());
    }

    SUBCASE("Invalid LIMIT 0") {
        DiagnosticEngine diag;
        bool ok = check_semantic("SELECT * FROM components LIMIT 0;", diag);
        CHECK_FALSE(ok);
        CHECK(diag.has_errors());
    }

    SUBCASE("Invalid DEPTH 0") {
        DiagnosticEngine diag;
        bool ok = check_semantic("SHOW TREE OF 'app' DEPTH 0;", diag);
        CHECK_FALSE(ok);
        CHECK(diag.has_errors());
    }

    SUBCASE("Pattern matching: Valid string operands") {
        DiagnosticEngine diag;
        bool ok = check_semantic("SELECT name FROM components WHERE name LIKE 'express%' AND purl CONTAINS 'npm';", diag);
        CHECK(ok);
        CHECK_FALSE(diag.has_errors());
    }

    SUBCASE("Pattern matching: Type mismatch with integer/float") {
        DiagnosticEngine diag;
        // score is Float, CONTAINS requires String
        bool ok1 = check_semantic("SELECT * FROM vulnerabilities WHERE score CONTAINS '7';", diag);
        CHECK_FALSE(ok1);
        CHECK(diag.has_errors());

        DiagnosticEngine diag2;
        // cwe is Integer, LIKE requires String
        bool ok2 = check_semantic("SELECT * FROM vulnerabilities WHERE cwe LIKE '500%';", diag2);
        CHECK_FALSE(ok2);
        CHECK(diag2.has_errors());

        DiagnosticEngine diag3;
        // name is String, comparing with integer literal via LIKE is invalid
        bool ok3 = check_semantic("SELECT * FROM components WHERE name LIKE 42;", diag3);
        CHECK_FALSE(ok3);
        CHECK(diag3.has_errors());
    }
}
