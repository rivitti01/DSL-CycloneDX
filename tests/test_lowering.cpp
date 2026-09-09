#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "sbom_dsl/lexer/lexer.hpp"
#include "sbom_dsl/parser/parser.hpp"
#include "sbom_dsl/lowering/query_lowerer.hpp"
#include "sbom_dsl/ir/ir_printer.hpp"

using namespace sbom_dsl;

static IRPlan parse_and_lower(const std::string& query) {
    DiagnosticEngine diag;
    Lexer lexer(query, "test.dsl", diag);
    auto tokens = lexer.tokenize();
    Parser parser(std::move(tokens), diag);
    auto prog = parser.parse_program();
    REQUIRE_FALSE(diag.has_errors());
    REQUIRE(prog != nullptr);
    REQUIRE(prog->statements.size() == 1);

    QueryLowerer lowerer;
    return lowerer.lower(*prog->statements[0]);
}

TEST_CASE("Lowering: Select statement to Relational IR") {
    std::string q = "SELECT name, version FROM components WHERE type = 'library' ORDER BY name ASC LIMIT 10;";
    auto plan = parse_and_lower(q);
    REQUIRE(plan.root != nullptr);
    CHECK(plan.root->type() == IRNodeType::Project);

    auto* proj = dynamic_cast<IRProject*>(plan.root.get());
    REQUIRE(proj != nullptr);
    REQUIRE(proj->child != nullptr);
    CHECK(proj->child->type() == IRNodeType::Limit);

    auto* limit = dynamic_cast<IRLimit*>(proj->child.get());
    REQUIRE(limit != nullptr);
    CHECK(limit->limit == 10);
    REQUIRE(limit->child != nullptr);
    CHECK(limit->child->type() == IRNodeType::Sort);

    auto* sort = dynamic_cast<IRSort*>(limit->child.get());
    REQUIRE(sort != nullptr);
    CHECK(sort->column == "name");
    CHECK(sort->ascending);
    REQUIRE(sort->child != nullptr);
    CHECK(sort->child->type() == IRNodeType::Filter);

    auto* filter = dynamic_cast<IRFilter*>(sort->child.get());
    REQUIRE(filter != nullptr);
    REQUIRE(filter->child != nullptr);
    CHECK(filter->child->type() == IRNodeType::Scan);
}

TEST_CASE("Lowering: WHO USES to GraphTraverse and HashJoin") {
    std::string q = "WHO USES 'log4j-core' TRANSITIVE IN 'bom.json';";
    auto plan = parse_and_lower(q);
    REQUIRE(plan.root != nullptr);
    REQUIRE(plan.bom_path.has_value());
    CHECK(*plan.bom_path == "bom.json");

    CHECK(plan.root->type() == IRNodeType::Project);
    auto* proj = dynamic_cast<IRProject*>(plan.root.get());
    REQUIRE(proj != nullptr);

    auto* join = dynamic_cast<IRHashJoin*>(proj->child.get());
    REQUIRE(join != nullptr);
    CHECK(join->left_key == "ref");
    CHECK(join->right_key == "bom-ref");

    auto* traverse = dynamic_cast<IRGraphTraverse*>(join->left.get());
    REQUIRE(traverse != nullptr);
    CHECK(traverse->target == "log4j-core");
    CHECK(traverse->direction == GraphDirection::Reverse);
    CHECK(traverse->transitive);

    auto* comp_scan = dynamic_cast<IRScan*>(join->right.get());
    REQUIRE(comp_scan != nullptr);
    CHECK(comp_scan->collection == "components");
}

TEST_CASE("Lowering: FIND VULNERABLE LIBRARIES to Join") {
    std::string q = "FIND VULNERABLE LIBRARIES SEVERITY >= HIGH IN 'bom.json';";
    auto plan = parse_and_lower(q);
    REQUIRE(plan.root != nullptr);

    auto* proj = dynamic_cast<IRProject*>(plan.root.get());
    REQUIRE(proj != nullptr);

    auto* join = dynamic_cast<IRHashJoin*>(proj->child.get());
    REQUIRE(join != nullptr);
    CHECK(join->left_key == "affects");
    CHECK(join->right_key == "bom-ref");

    // Left side: vuln filtered by severity
    CHECK(join->left->type() == IRNodeType::Filter);
    // Right side: comp filtered by library
    CHECK(join->right->type() == IRNodeType::Filter);
}

TEST_CASE("Lowering: SHOW TREE to Forward GraphTraverse") {
    std::string q = "SHOW TREE OF 'juice-shop' DEPTH 3;";
    auto plan = parse_and_lower(q);
    REQUIRE(plan.root != nullptr);

    auto* proj = dynamic_cast<IRProject*>(plan.root.get());
    REQUIRE(proj != nullptr);

    auto* join = dynamic_cast<IRHashJoin*>(proj->child.get());
    REQUIRE(join != nullptr);

    auto* traverse = dynamic_cast<IRGraphTraverse*>(join->left.get());
    REQUIRE(traverse != nullptr);
    CHECK(traverse->target == "juice-shop");
    CHECK(traverse->direction == GraphDirection::Forward);
    REQUIRE(traverse->max_depth.has_value());
    CHECK(*traverse->max_depth == 3);
}

TEST_CASE("Lowering: FIND BLAST RADIUS") {
    std::string q = "FIND BLAST RADIUS OF 'CVE-2021-44228';";
    auto plan = parse_and_lower(q);
    REQUIRE(plan.root != nullptr);
    CHECK(plan.root->type() == IRNodeType::BlastRadius);

    auto* blast = dynamic_cast<IRBlastRadius*>(plan.root.get());
    REQUIRE(blast != nullptr);
    CHECK(blast->vulnerability_id == "CVE-2021-44228");
}

TEST_CASE("Lowering: Policy assertions (ASSERT NO ...)") {
    SUBCASE("ASSERT NO VULNERABILITIES lowers to HashJoin on affects and components") {
        std::string q = "ASSERT NO VULNERABILITIES SEVERITY >= HIGH;";
        auto plan = parse_and_lower(q);
        REQUIRE(plan.root != nullptr);
        CHECK(plan.is_assertion);
        CHECK(plan.assertion_title == "ASSERT NO VULNERABILITIES SEVERITY >= HIGH");

        auto* proj = dynamic_cast<IRProject*>(plan.root.get());
        REQUIRE(proj != nullptr);

        auto* join = dynamic_cast<IRHashJoin*>(proj->child.get());
        REQUIRE(join != nullptr);
        CHECK(join->left_key == "affects");
        CHECK(join->right_key == "bom-ref");

        // Left side: vuln filtered by severity
        CHECK(join->left->type() == IRNodeType::Filter);
        // Right side: comp scan
        CHECK(join->right->type() == IRNodeType::Scan);
    }

    SUBCASE("ASSERT NO COMPONENTS with WHERE clause") {
        std::string q = "ASSERT NO COMPONENTS WHERE type = 'framework';";
        auto plan = parse_and_lower(q);
        REQUIRE(plan.root != nullptr);
        CHECK(plan.is_assertion);
        CHECK(plan.assertion_title == "ASSERT NO COMPONENTS");

        auto* proj = dynamic_cast<IRProject*>(plan.root.get());
        REQUIRE(proj != nullptr);

        auto* filter = dynamic_cast<IRFilter*>(proj->child.get());
        REQUIRE(filter != nullptr);
        CHECK(filter->child->type() == IRNodeType::Scan);

        auto* scan = dynamic_cast<IRScan*>(filter->child.get());
        REQUIRE(scan != nullptr);
        CHECK(scan->collection == "components");
    }

    SUBCASE("ASSERT NO LIBRARIES filters type = 'library'") {
        std::string q = "ASSERT NO LIBRARIES;";
        auto plan = parse_and_lower(q);
        REQUIRE(plan.root != nullptr);
        CHECK(plan.is_assertion);
        CHECK(plan.assertion_title == "ASSERT NO LIBRARIES");

        auto* proj = dynamic_cast<IRProject*>(plan.root.get());
        REQUIRE(proj != nullptr);

        auto* filter = dynamic_cast<IRFilter*>(proj->child.get());
        REQUIRE(filter != nullptr);
        CHECK(filter->child->type() == IRNodeType::Scan);
    }
}
