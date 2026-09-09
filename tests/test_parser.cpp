#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "sbom_dsl/lexer/lexer.hpp"
#include "sbom_dsl/parser/parser.hpp"
#include "sbom_dsl/ast/ast_printer.hpp"

using namespace sbom_dsl;

static std::unique_ptr<ProgramNode> parse(const std::string& src, DiagnosticEngine& diag) {
    Lexer lexer(src, "test.dsl", diag);
    auto tokens = lexer.tokenize();
    Parser parser(std::move(tokens), diag);
    return parser.parse_program();
}

TEST_CASE("Parser: Select statement variations") {
    SUBCASE("SELECT * FROM components") {
        DiagnosticEngine diag;
        auto prog = parse("SELECT * FROM components;", diag);
        CHECK_FALSE(diag.has_errors());
        REQUIRE(prog->statements.size() == 1);

        auto* select = dynamic_cast<SelectStatement*>(prog->statements[0].get());
        REQUIRE(select != nullptr);
        CHECK(select->projections.empty()); // empty means '*'
        CHECK(select->collection == "components");
        CHECK(select->where_clause == nullptr);
    }

    SUBCASE("SELECT with columns, WHERE, ORDER BY, LIMIT, and IN") {
        DiagnosticEngine diag;
        std::string q = "SELECT name, version, purl FROM components IN 'bom.json' "
                        "WHERE type = 'library' AND version != '1.0' "
                        "ORDER BY name DESC LIMIT 25;";
        auto prog = parse(q, diag);
        CHECK_FALSE(diag.has_errors());
        REQUIRE(prog->statements.size() == 1);

        auto* select = dynamic_cast<SelectStatement*>(prog->statements[0].get());
        REQUIRE(select != nullptr);
        REQUIRE(select->projections.size() == 3);
        CHECK(select->projections[0] == "name");
        CHECK(select->projections[1] == "version");
        CHECK(select->projections[2] == "purl");
        CHECK(select->collection == "components");
        REQUIRE(select->bom_path.has_value());
        CHECK(*select->bom_path == "bom.json");
        REQUIRE(select->where_clause != nullptr);
        REQUIRE(select->order_by.has_value());
        CHECK(select->order_by->column == "name");
        CHECK_FALSE(select->order_by->ascending);
        REQUIRE(select->limit.has_value());
        CHECK(*select->limit == 25);
    }
}

TEST_CASE("Parser: Expression operator precedence (Pratt parsing)") {
    DiagnosticEngine diag;
    // AND should bind tighter than OR: a = 1 OR b = 2 AND c = 3
    // AST should be: OR(left = (a = 1), right = AND(b = 2, c = 3))
    std::string q = "SELECT * FROM components WHERE a = 1 OR b = 2 AND c = 3;";
    auto prog = parse(q, diag);
    CHECK_FALSE(diag.has_errors());

    auto* select = dynamic_cast<SelectStatement*>(prog->statements[0].get());
    REQUIRE(select != nullptr);
    REQUIRE(select->where_clause != nullptr);

    auto* root_or = dynamic_cast<BinaryOpExpr*>(select->where_clause.get());
    REQUIRE(root_or != nullptr);
    CHECK(root_or->op == BinaryOperator::Or);

    auto* left_comp = dynamic_cast<BinaryOpExpr*>(root_or->left.get());
    REQUIRE(left_comp != nullptr);
    CHECK(left_comp->op == BinaryOperator::Equal);

    auto* right_and = dynamic_cast<BinaryOpExpr*>(root_or->right.get());
    REQUIRE(right_and != nullptr);
    CHECK(right_and->op == BinaryOperator::And);
}

TEST_CASE("Parser: Unary NOT and Parentheses") {
    DiagnosticEngine diag;
    std::string q = "SELECT * FROM components WHERE NOT (type = 'framework' OR active = false);";
    auto prog = parse(q, diag);
    CHECK_FALSE(diag.has_errors());

    auto* select = dynamic_cast<SelectStatement*>(prog->statements[0].get());
    REQUIRE(select != nullptr);
    auto* not_expr = dynamic_cast<UnaryOpExpr*>(select->where_clause.get());
    REQUIRE(not_expr != nullptr);
    CHECK(not_expr->op == UnaryOperator::Not);

    auto* inner_or = dynamic_cast<BinaryOpExpr*>(not_expr->operand.get());
    REQUIRE(inner_or != nullptr);
    CHECK(inner_or->op == BinaryOperator::Or);
}

TEST_CASE("Parser: WHO USES statement") {
    DiagnosticEngine diag;
    auto prog = parse("WHO USES 'log4j-core' DIRECT IN 'cyclonedx.json';", diag);
    CHECK_FALSE(diag.has_errors());
    REQUIRE(prog->statements.size() == 1);

    auto* who = dynamic_cast<WhoUsesStatement*>(prog->statements[0].get());
    REQUIRE(who != nullptr);
    CHECK(who->target_component == "log4j-core");
    CHECK_FALSE(who->is_transitive);
    REQUIRE(who->bom_path.has_value());
    CHECK(*who->bom_path == "cyclonedx.json");
}

TEST_CASE("Parser: FIND VULNERABLE statement") {
    DiagnosticEngine diag;
    auto prog = parse("FIND VULNERABLE LIBRARIES SEVERITY >= HIGH WHERE cwe = 502;", diag);
    CHECK_FALSE(diag.has_errors());
    REQUIRE(prog->statements.size() == 1);

    auto* find = dynamic_cast<FindVulnerableStatement*>(prog->statements[0].get());
    REQUIRE(find != nullptr);
    CHECK(find->libraries_only);
    REQUIRE(find->severity_op.has_value());
    CHECK(*find->severity_op == BinaryOperator::GreaterEqual);
    REQUIRE(find->severity_level.has_value());
    CHECK(*find->severity_level == SeverityLevel::High);
    REQUIRE(find->where_clause != nullptr);
}

TEST_CASE("Parser: SHOW TREE statement") {
    DiagnosticEngine diag;
    auto prog = parse("SHOW TREE OF 'juice-shop' DEPTH 3 IN 'bom.json';", diag);
    CHECK_FALSE(diag.has_errors());
    REQUIRE(prog->statements.size() == 1);

    auto* tree = dynamic_cast<ShowTreeStatement*>(prog->statements[0].get());
    REQUIRE(tree != nullptr);
    REQUIRE(tree->root_component.has_value());
    CHECK(*tree->root_component == "juice-shop");
    REQUIRE(tree->max_depth.has_value());
    CHECK(*tree->max_depth == 3);
}

TEST_CASE("Parser: FIND BLAST RADIUS statement") {
    DiagnosticEngine diag;
    auto prog = parse("FIND BLAST RADIUS OF 'CVE-2021-44228' IN 'bom.json';", diag);
    CHECK_FALSE(diag.has_errors());
    REQUIRE(prog->statements.size() == 1);

    auto* blast = dynamic_cast<BlastRadiusStatement*>(prog->statements[0].get());
    REQUIRE(blast != nullptr);
    CHECK(blast->vulnerability_id == "CVE-2021-44228");
}

TEST_CASE("Parser: Syntax errors") {
    SUBCASE("Missing FROM in SELECT") {
        DiagnosticEngine diag;
        auto prog = parse("SELECT name WHERE x = 1;", diag);
        CHECK(diag.has_errors());
    }

    SUBCASE("Missing operand in binary expression") {
        DiagnosticEngine diag;
        auto prog = parse("SELECT * FROM components WHERE a = ;", diag);
        CHECK(diag.has_errors());
    }
}

TEST_CASE("Parser: Pattern matching expressions (LIKE, CONTAINS, MATCHES)") {
    DiagnosticEngine diag;
    std::string q = "SELECT name FROM components WHERE name LIKE 'express%' AND (purl CONTAINS 'npm' OR description MATCHES '^Fast');";
    auto prog = parse(q, diag);
    CHECK_FALSE(diag.has_errors());
    REQUIRE(prog != nullptr);
    REQUIRE(prog->statements.size() == 1);

    auto* select = dynamic_cast<SelectStatement*>(prog->statements[0].get());
    REQUIRE(select != nullptr);
    REQUIRE(select->where_clause != nullptr);

    // Root should be AND
    auto* root_and = dynamic_cast<BinaryOpExpr*>(select->where_clause.get());
    REQUIRE(root_and != nullptr);
    CHECK(root_and->op == BinaryOperator::And);

    // Left is name LIKE 'express%'
    auto* left_like = dynamic_cast<BinaryOpExpr*>(root_and->left.get());
    REQUIRE(left_like != nullptr);
    CHECK(left_like->op == BinaryOperator::Like);
    auto* left_col = dynamic_cast<ColumnRefExpr*>(left_like->left.get());
    REQUIRE(left_col != nullptr);
    CHECK(left_col->full_path() == "name");
    auto* left_lit = dynamic_cast<LiteralExpr*>(left_like->right.get());
    REQUIRE(left_lit != nullptr);
    CHECK(std::get<std::string>(left_lit->value) == "express%");

    // Right is (purl CONTAINS 'npm' OR description MATCHES '^Fast')
    auto* right_or = dynamic_cast<BinaryOpExpr*>(root_and->right.get());
    REQUIRE(right_or != nullptr);
    CHECK(right_or->op == BinaryOperator::Or);

    auto* purl_contains = dynamic_cast<BinaryOpExpr*>(right_or->left.get());
    REQUIRE(purl_contains != nullptr);
    CHECK(purl_contains->op == BinaryOperator::Contains);

    auto* desc_matches = dynamic_cast<BinaryOpExpr*>(right_or->right.get());
    REQUIRE(desc_matches != nullptr);
    CHECK(desc_matches->op == BinaryOperator::Matches);
}

TEST_CASE("Parser: Policy assertion statements (ASSERT NO ...)") {
    SUBCASE("ASSERT NO VULNERABILITIES with severity level") {
        DiagnosticEngine diag;
        std::string q = "ASSERT NO VULNERABILITIES SEVERITY >= CRITICAL;";
        auto prog = parse(q, diag);
        CHECK_FALSE(diag.has_errors());
        REQUIRE(prog != nullptr);
        REQUIRE(prog->statements.size() == 1);

        auto* asrt = dynamic_cast<AssertStatement*>(prog->statements[0].get());
        REQUIRE(asrt != nullptr);
        CHECK(asrt->target == AssertTarget::Vulnerabilities);
        REQUIRE(asrt->severity_op.has_value());
        CHECK(*asrt->severity_op == BinaryOperator::GreaterEqual);
        REQUIRE(asrt->severity_level.has_value());
        CHECK(*asrt->severity_level == SeverityLevel::Critical);
        CHECK_FALSE(asrt->score_threshold.has_value());
        CHECK(asrt->where_clause == nullptr);
    }

    SUBCASE("ASSERT NO VULNERABILITIES with numeric score threshold") {
        DiagnosticEngine diag;
        std::string q = "ASSERT NO VULNERABILITIES SEVERITY > 10.0 IN 'bom.json';";
        auto prog = parse(q, diag);
        CHECK_FALSE(diag.has_errors());
        REQUIRE(prog != nullptr);
        REQUIRE(prog->statements.size() == 1);

        auto* asrt = dynamic_cast<AssertStatement*>(prog->statements[0].get());
        REQUIRE(asrt != nullptr);
        CHECK(asrt->target == AssertTarget::Vulnerabilities);
        REQUIRE(asrt->severity_op.has_value());
        CHECK(*asrt->severity_op == BinaryOperator::Greater);
        REQUIRE(asrt->score_threshold.has_value());
        CHECK(*asrt->score_threshold == doctest::Approx(10.0));
        CHECK_FALSE(asrt->severity_level.has_value());
        REQUIRE(asrt->bom_path.has_value());
        CHECK(*asrt->bom_path == "bom.json");
    }

    SUBCASE("ASSERT NO COMPONENTS WHERE clause") {
        DiagnosticEngine diag;
        std::string q = "ASSERT NO COMPONENTS WHERE type = 'framework';";
        auto prog = parse(q, diag);
        CHECK_FALSE(diag.has_errors());
        REQUIRE(prog != nullptr);
        REQUIRE(prog->statements.size() == 1);

        auto* asrt = dynamic_cast<AssertStatement*>(prog->statements[0].get());
        REQUIRE(asrt != nullptr);
        CHECK(asrt->target == AssertTarget::Components);
        CHECK_FALSE(asrt->severity_level.has_value());
        REQUIRE(asrt->where_clause != nullptr);
    }

    SUBCASE("ASSERT NO LIBRARIES simple") {
        DiagnosticEngine diag;
        std::string q = "ASSERT NO LIBRARIES;";
        auto prog = parse(q, diag);
        CHECK_FALSE(diag.has_errors());
        REQUIRE(prog != nullptr);
        REQUIRE(prog->statements.size() == 1);

        auto* asrt = dynamic_cast<AssertStatement*>(prog->statements[0].get());
        REQUIRE(asrt != nullptr);
        CHECK(asrt->target == AssertTarget::Libraries);
    }

    SUBCASE("Parser error: Missing NO after ASSERT") {
        DiagnosticEngine diag;
        auto prog = parse("ASSERT VULNERABILITIES;", diag);
        CHECK(diag.has_errors());
    }

    SUBCASE("Parser error: Missing target after ASSERT NO") {
        DiagnosticEngine diag;
        auto prog = parse("ASSERT NO ;", diag);
        CHECK(diag.has_errors());
    }

    SUBCASE("Parser error: Invalid severity level/score") {
        DiagnosticEngine diag;
        auto prog = parse("ASSERT NO VULNERABILITIES SEVERITY FOOBAR;", diag);
        CHECK(diag.has_errors());
    }
}
