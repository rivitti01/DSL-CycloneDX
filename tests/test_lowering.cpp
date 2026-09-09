#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "sbom_dsl/lexer/lexer.hpp"
#include "sbom_dsl/parser/parser.hpp"
#include "sbom_dsl/lowering/query_lowerer.hpp"
#include "sbom_dsl/ir/ir_printer.hpp"
#include "sbom_dsl/ir/ir_optimizer.hpp"

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

TEST_CASE("IROptimizer: Constant Folding and Simplification") {
    IROptimizer optimizer;

    SUBCASE("Fold WHERE 1 = 1 AND name = 'express'") {
        std::string q = "SELECT name FROM components WHERE 1 = 1 AND name = 'express';";
        auto plan = parse_and_lower(q);

        // Pre-optimization check
        auto* proj_pre = dynamic_cast<IRProject*>(plan.root.get());
        REQUIRE(proj_pre != nullptr);
        auto* filter_pre = dynamic_cast<IRFilter*>(proj_pre->child.get());
        REQUIRE(filter_pre != nullptr);
        auto* and_bin_pre = dynamic_cast<BinaryOpExpr*>(filter_pre->predicate.get());
        REQUIRE(and_bin_pre != nullptr);
        CHECK(and_bin_pre->op == BinaryOperator::And);

        // Post-optimization check
        auto opt_plan = optimizer.optimize(plan);
        REQUIRE(opt_plan.root != nullptr);
        auto* proj_opt = dynamic_cast<IRProject*>(opt_plan.root.get());
        REQUIRE(proj_opt != nullptr);
        auto* filter_opt = dynamic_cast<IRFilter*>(proj_opt->child.get());
        REQUIRE(filter_opt != nullptr);

        // Filter predicate must now be simplified directly to: name = 'express'
        auto* eq_bin = dynamic_cast<BinaryOpExpr*>(filter_opt->predicate.get());
        REQUIRE(eq_bin != nullptr);
        CHECK(eq_bin->op == BinaryOperator::Equal);

        auto* col = dynamic_cast<ColumnRefExpr*>(eq_bin->left.get());
        REQUIRE(col != nullptr);
        CHECK(col->full_path() == "name");

        auto* lit = dynamic_cast<LiteralExpr*>(eq_bin->right.get());
        REQUIRE(lit != nullptr);
        CHECK(lit->value_as_string() == "\"express\"");
    }

    SUBCASE("Dead filter elimination for tautology WHERE 1 = 1") {
        std::string q = "SELECT name FROM components WHERE 1 = 1;";
        auto plan = parse_and_lower(q);

        // Pre-optimization has IRFilter
        auto* proj_pre = dynamic_cast<IRProject*>(plan.root.get());
        REQUIRE(proj_pre != nullptr);
        CHECK(proj_pre->child->type() == IRNodeType::Filter);

        // Post-optimization has eliminated the filter completely!
        auto opt_plan = optimizer.optimize(plan);
        auto* proj_opt = dynamic_cast<IRProject*>(opt_plan.root.get());
        REQUIRE(proj_opt != nullptr);
        CHECK(proj_opt->child->type() == IRNodeType::Scan);
    }

    SUBCASE("Fold WHERE 1 = 0 AND name = 'express' to false literal") {
        std::string q = "SELECT name FROM components WHERE 1 = 0 AND name = 'express';";
        auto plan = parse_and_lower(q);

        auto opt_plan = optimizer.optimize(plan);
        auto* proj_opt = dynamic_cast<IRProject*>(opt_plan.root.get());
        REQUIRE(proj_opt != nullptr);
        auto* filter_opt = dynamic_cast<IRFilter*>(proj_opt->child.get());
        REQUIRE(filter_opt != nullptr);

        CHECK(IROptimizer::is_false_literal(filter_opt->predicate.get()));
    }

    SUBCASE("Fold double negation NOT (1 = 0) AND name = 'express'") {
        std::string q = "SELECT name FROM components WHERE NOT (1 = 0) AND name = 'express';";
        auto plan = parse_and_lower(q);

        auto opt_plan = optimizer.optimize(plan);
        auto* proj_opt = dynamic_cast<IRProject*>(opt_plan.root.get());
        REQUIRE(proj_opt != nullptr);
        auto* filter_opt = dynamic_cast<IRFilter*>(proj_opt->child.get());
        REQUIRE(filter_opt != nullptr);

        auto* eq_bin = dynamic_cast<BinaryOpExpr*>(filter_opt->predicate.get());
        REQUIRE(eq_bin != nullptr);
        CHECK(eq_bin->op == BinaryOperator::Equal);
        auto* col = dynamic_cast<ColumnRefExpr*>(eq_bin->left.get());
        REQUIRE(col != nullptr);
        CHECK(col->full_path() == "name");
    }

    SUBCASE("Fold nested complex constants: (10 > 5 AND 'a' = 'a') AND name = 'express'") {
        std::string q = "SELECT name FROM components WHERE (10 > 5 AND 'a' = 'a') AND name = 'express';";
        auto plan = parse_and_lower(q);

        auto opt_plan = optimizer.optimize(plan);
        auto* proj_opt = dynamic_cast<IRProject*>(opt_plan.root.get());
        REQUIRE(proj_opt != nullptr);
        auto* filter_opt = dynamic_cast<IRFilter*>(proj_opt->child.get());
        REQUIRE(filter_opt != nullptr);

        auto* eq_bin = dynamic_cast<BinaryOpExpr*>(filter_opt->predicate.get());
        REQUIRE(eq_bin != nullptr);
        CHECK(eq_bin->op == BinaryOperator::Equal);
    }
}

TEST_CASE("IROptimizer: Predicate Pushdown") {
    IROptimizer optimizer;

    SUBCASE("Pushdown component filter to right branch of join") {
        std::string q = "FIND VULNERABLE LIBRARIES SEVERITY >= HIGH WHERE name = 'log4j-core';";
        auto plan = parse_and_lower(q);

        // Pre-optimization: Filter is on top of HashJoin
        auto* proj_pre = dynamic_cast<IRProject*>(plan.root.get());
        REQUIRE(proj_pre != nullptr);
        auto* filter_pre = dynamic_cast<IRFilter*>(proj_pre->child.get());
        REQUIRE(filter_pre != nullptr);
        CHECK(filter_pre->child->type() == IRNodeType::HashJoin);

        // Post-optimization: Filter has been pushed down to the right branch (components)!
        auto opt_plan = optimizer.optimize(plan);
        auto* proj_opt = dynamic_cast<IRProject*>(opt_plan.root.get());
        REQUIRE(proj_opt != nullptr);
        CHECK(proj_opt->child->type() == IRNodeType::HashJoin);

        auto* join_opt = dynamic_cast<IRHashJoin*>(proj_opt->child.get());
        REQUIRE(join_opt != nullptr);
        // Left branch remains vulnerabilities filter
        CHECK(join_opt->left->type() == IRNodeType::Filter);
        // Right branch has the pushed-down filter on components!
        CHECK(join_opt->right->type() == IRNodeType::Filter);

        auto* right_filter = dynamic_cast<IRFilter*>(join_opt->right.get());
        REQUIRE(right_filter != nullptr);
        // Scans components underneath
        CHECK(right_filter->child->type() == IRNodeType::Scan);
        // Predicate contains name filter
        std::string right_desc = right_filter->description();
        CHECK(right_desc.find("name") != std::string::npos);
        CHECK(right_desc.find("library") != std::string::npos);
    }

    SUBCASE("Pushdown vulnerability filter to left branch of join") {
        std::string q = "FIND VULNERABLE LIBRARIES SEVERITY >= HIGH WHERE cwe = 502;";
        auto plan = parse_and_lower(q);

        auto opt_plan = optimizer.optimize(plan);
        auto* proj_opt = dynamic_cast<IRProject*>(opt_plan.root.get());
        REQUIRE(proj_opt != nullptr);
        CHECK(proj_opt->child->type() == IRNodeType::HashJoin);

        auto* join_opt = dynamic_cast<IRHashJoin*>(proj_opt->child.get());
        REQUIRE(join_opt != nullptr);

        // Left branch has cwe filter merged
        auto* left_filter = dynamic_cast<IRFilter*>(join_opt->left.get());
        REQUIRE(left_filter != nullptr);
        std::string left_desc = left_filter->description();
        CHECK(left_desc.find("cwe") != std::string::npos);
        CHECK(left_desc.find("ratings.severity") != std::string::npos);
    }

    SUBCASE("Pushdown composite WHERE splitting across both join branches") {
        std::string q = "FIND VULNERABLE LIBRARIES SEVERITY >= HIGH WHERE cwe = 502 AND name = 'log4j-core';";
        auto plan = parse_and_lower(q);

        auto opt_plan = optimizer.optimize(plan);
        auto* proj_opt = dynamic_cast<IRProject*>(opt_plan.root.get());
        REQUIRE(proj_opt != nullptr);
        CHECK(proj_opt->child->type() == IRNodeType::HashJoin);

        auto* join_opt = dynamic_cast<IRHashJoin*>(proj_opt->child.get());
        REQUIRE(join_opt != nullptr);

        // Left branch contains cwe
        auto* left_filter = dynamic_cast<IRFilter*>(join_opt->left.get());
        REQUIRE(left_filter != nullptr);
        CHECK(left_filter->description().find("cwe") != std::string::npos);

        // Right branch contains name
        auto* right_filter = dynamic_cast<IRFilter*>(join_opt->right.get());
        REQUIRE(right_filter != nullptr);
        CHECK(right_filter->description().find("name") != std::string::npos);
    }

    SUBCASE("Pushdown past IRSort") {
        // Manually build Filter over Sort: Filter(name = 'express', Sort(name ASC, Scan("components")))
        auto scan = std::make_unique<IRScan>("components");
        auto sort = std::make_unique<IRSort>(std::move(scan), "name", true);
        auto col = std::make_unique<ColumnRefExpr>(std::vector<std::string>{"name"}, SourceLocation{});
        auto lit = std::make_unique<LiteralExpr>(std::string("express"), SourceLocation{});
        auto pred = std::make_unique<BinaryOpExpr>(BinaryOperator::Equal, std::move(col), std::move(lit), SourceLocation{});
        auto filter = std::make_unique<IRFilter>(std::move(sort), std::move(pred));

        auto pushed = optimizer.pushdown_predicates(std::move(filter));
        REQUIRE(pushed != nullptr);
        CHECK(pushed->type() == IRNodeType::Sort);
        auto* sort_res = dynamic_cast<IRSort*>(pushed.get());
        REQUIRE(sort_res != nullptr);
        CHECK(sort_res->child->type() == IRNodeType::Filter);
        auto* filter_res = dynamic_cast<IRFilter*>(sort_res->child.get());
        REQUIRE(filter_res != nullptr);
        CHECK(filter_res->child->type() == IRNodeType::Scan);
    }
}

TEST_CASE("Lowering: Aggregations and GROUP BY") {
    SUBCASE("Scalar aggregate: SELECT COUNT(*) FROM components WHERE type = 'library'") {
        std::string q = "SELECT COUNT(*) FROM components WHERE type = 'library';";
        auto plan = parse_and_lower(q);
        REQUIRE(plan.root != nullptr);
        CHECK(plan.root->type() == IRNodeType::Project);

        auto* proj = dynamic_cast<IRProject*>(plan.root.get());
        REQUIRE(proj != nullptr);
        REQUIRE(proj->child != nullptr);
        CHECK(proj->child->type() == IRNodeType::Aggregate);

        auto* agg = dynamic_cast<IRAggregate*>(proj->child.get());
        REQUIRE(agg != nullptr);
        CHECK(agg->group_by_columns.empty());
        REQUIRE(agg->aggregates.size() == 1);
        CHECK(agg->aggregates[0].kind == AggregateFunction::Kind::Count);
        CHECK(agg->aggregates[0].argument == "*");
        CHECK(agg->aggregates[0].result_column == "COUNT(*)");

        REQUIRE(agg->child != nullptr);
        CHECK(agg->child->type() == IRNodeType::Filter);

        auto* filter = dynamic_cast<IRFilter*>(agg->child.get());
        REQUIRE(filter != nullptr);
        REQUIRE(filter->child != nullptr);
        CHECK(filter->child->type() == IRNodeType::Scan);
    }

    SUBCASE("Grouped aggregate: SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity ORDER BY severity ASC LIMIT 5") {
        std::string q = "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity ORDER BY severity ASC LIMIT 5;";
        auto plan = parse_and_lower(q);
        REQUIRE(plan.root != nullptr);
        CHECK(plan.root->type() == IRNodeType::Project);

        auto* proj = dynamic_cast<IRProject*>(plan.root.get());
        REQUIRE(proj != nullptr);
        REQUIRE(proj->child != nullptr);
        CHECK(proj->child->type() == IRNodeType::Limit);

        auto* limit = dynamic_cast<IRLimit*>(proj->child.get());
        REQUIRE(limit != nullptr);
        CHECK(limit->limit == 5);
        REQUIRE(limit->child != nullptr);
        CHECK(limit->child->type() == IRNodeType::Sort);

        auto* sort = dynamic_cast<IRSort*>(limit->child.get());
        REQUIRE(sort != nullptr);
        CHECK(sort->column == "severity");
        CHECK(sort->ascending);
        REQUIRE(sort->child != nullptr);
        CHECK(sort->child->type() == IRNodeType::Aggregate);

        auto* agg = dynamic_cast<IRAggregate*>(sort->child.get());
        REQUIRE(agg != nullptr);
        REQUIRE(agg->group_by_columns.size() == 1);
        CHECK(agg->group_by_columns[0] == "severity");
        REQUIRE(agg->aggregates.size() == 1);
        CHECK(agg->aggregates[0].result_column == "COUNT(*)");

        REQUIRE(agg->child != nullptr);
        CHECK(agg->child->type() == IRNodeType::Scan);
    }

    SUBCASE("IRPrinter and IROptimizer on IRAggregate plan") {
        std::string q = "SELECT type, COUNT(*) FROM components WHERE 1 = 1 AND type = 'library' GROUP BY type;";
        auto plan = parse_and_lower(q);

        // Verify IRPrinter
        std::string printed = IRPrinter::print(plan);
        CHECK(printed.find("Aggregate(group_by=[type], funcs=[COUNT(*)])") != std::string::npos);

        // Verify IROptimizer constant folding on child of aggregate
        IROptimizer opt;
        auto opt_plan = opt.optimize(plan);
        REQUIRE(opt_plan.root != nullptr);

        auto* proj = dynamic_cast<IRProject*>(opt_plan.root.get());
        REQUIRE(proj != nullptr);
        auto* agg = dynamic_cast<IRAggregate*>(proj->child.get());
        REQUIRE(agg != nullptr);
        auto* filter = dynamic_cast<IRFilter*>(agg->child.get());
        REQUIRE(filter != nullptr);

        // Predicate 1 = 1 was folded, leaving only type = 'library'
        auto* eq = dynamic_cast<BinaryOpExpr*>(filter->predicate.get());
        REQUIRE(eq != nullptr);
        CHECK(eq->op == BinaryOperator::Equal);
    }
}

