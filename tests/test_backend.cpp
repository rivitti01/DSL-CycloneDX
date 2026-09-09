#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "sbom_dsl/lexer/lexer.hpp"
#include "sbom_dsl/parser/parser.hpp"
#include "sbom_dsl/lowering/query_lowerer.hpp"
#include "sbom_dsl/backend/native_engine.hpp"
#include "sbom_dsl/backend/sbom_utility_codegen.hpp"
#include "sbom_dsl/backend/result_formatter.hpp"
#include "sbom_dsl/ir/ir_optimizer.hpp"

using namespace sbom_dsl;

static const std::string FIXTURE_PATH = std::string(TEST_FIXTURE_DIR) + "/sample_cyclonedx.json";

static QueryResult run_query(const std::string& query) {
    DiagnosticEngine diag;
    Lexer lexer(query, "test.dsl", diag);
    auto tokens = lexer.tokenize();
    Parser parser(std::move(tokens), diag);
    auto prog = parser.parse_program();
    REQUIRE_FALSE(diag.has_errors());
    REQUIRE(prog != nullptr);
    REQUIRE(prog->statements.size() == 1);

    QueryLowerer lowerer;
    auto plan = lowerer.lower(*prog->statements[0]);

    NativeEngine engine;
    bool ok = engine.load_bom_file(FIXTURE_PATH, diag);
    REQUIRE(ok);

    return engine.execute(plan, diag);
}

static QueryResult run_optimized_query(const std::string& query) {
    DiagnosticEngine diag;
    Lexer lexer(query, "test.dsl", diag);
    auto tokens = lexer.tokenize();
    Parser parser(std::move(tokens), diag);
    auto prog = parser.parse_program();
    REQUIRE_FALSE(diag.has_errors());
    REQUIRE(prog != nullptr);
    REQUIRE(prog->statements.size() == 1);

    QueryLowerer lowerer;
    auto plan = lowerer.lower(*prog->statements[0]);

    IROptimizer optimizer;
    auto opt_plan = optimizer.optimize(plan);

    NativeEngine engine;
    bool ok = engine.load_bom_file(FIXTURE_PATH, diag);
    REQUIRE(ok);

    return engine.execute(opt_plan, diag);
}

TEST_CASE("Backend: SELECT components") {
    std::string q = "SELECT name, version FROM components WHERE type = 'library' ORDER BY name ASC;";
    auto res = run_query(q);

    CHECK_FALSE(res.is_empty());
    CHECK(res.columns.size() == 2);
    CHECK(res.columns[0] == "name");
    CHECK(res.columns[1] == "version");
    CHECK(res.rows.size() == 5);

    // Verify ordering
    CHECK(res.rows[0][0] == "body-parser");
    CHECK(res.rows[1][0] == "express");
    CHECK(res.rows[2][0] == "lodash");
    CHECK(res.rows[3][0] == "log4j-core");
    CHECK(res.rows[4][0] == "qs");
}

TEST_CASE("Backend: WHO USES 'qs' (Reverse Graph Traversal)") {
    // qs is used by body-parser, which is used by express, which is used by my-web-app
    std::string q = "WHO USES 'qs' TRANSITIVE;";
    auto res = run_query(q);

    CHECK_FALSE(res.is_empty());
    // Should find body-parser, express, and my-web-app
    std::vector<std::string> found_names;
    for (const auto& row : res.rows) {
        found_names.push_back(row[0]);
    }
    CHECK(found_names.size() == 3);
    CHECK(std::find(found_names.begin(), found_names.end(), "body-parser") != found_names.end());
    CHECK(std::find(found_names.begin(), found_names.end(), "express") != found_names.end());
    CHECK(std::find(found_names.begin(), found_names.end(), "my-web-app") != found_names.end());
}

TEST_CASE("Backend: FIND VULNERABLE LIBRARIES (Relational Join)") {
    std::string q = "FIND VULNERABLE LIBRARIES SEVERITY >= HIGH;";
    auto res = run_query(q);

    CHECK_FALSE(res.is_empty());
    REQUIRE(res.rows.size() == 2);

    std::vector<std::string> vulns;
    for (const auto& row : res.rows) {
        vulns.push_back(row[0]); // component name
    }
    CHECK(std::find(vulns.begin(), vulns.end(), "log4j-core") != vulns.end());
    CHECK(std::find(vulns.begin(), vulns.end(), "qs") != vulns.end());
}

TEST_CASE("Backend: SHOW TREE (Forward Graph Traversal)") {
    std::string q = "SHOW TREE OF 'my-web-app' DEPTH 2;";
    auto res = run_query(q);

    CHECK_FALSE(res.is_empty());
    // Depth 1: express, log4j-core
    // Depth 2: body-parser
    std::vector<std::string> names;
    for (const auto& row : res.rows) {
        names.push_back(row[0]);
    }
    CHECK(std::find(names.begin(), names.end(), "express") != names.end());
    CHECK(std::find(names.begin(), names.end(), "log4j-core") != names.end());
    CHECK(std::find(names.begin(), names.end(), "body-parser") != names.end());
}

TEST_CASE("Backend: FIND BLAST RADIUS OF 'CVE-2022-29244'") {
    std::string q = "FIND BLAST RADIUS OF 'CVE-2022-29244';";
    auto res = run_query(q);

    REQUIRE(res.blast_radius.has_value());
    auto& metrics = *res.blast_radius;

    CHECK(metrics.vulnerability_id == "CVE-2022-29244");
    CHECK(metrics.severity == "high");
    CHECK(metrics.score == doctest::Approx(7.5));
    CHECK(metrics.directly_affected_components == 1); // qs
    CHECK(metrics.transitively_affected_components == 4); // qs, body-parser, express, my-web-app
    CHECK(metrics.root_application_affected == true);
}

TEST_CASE("Backend: sbom-utility CodeGen") {
    DiagnosticEngine diag;
    QueryLowerer lowerer;

    SUBCASE("Mappable select query") {
        Lexer lex("SELECT name, version FROM components WHERE type = 'library';", "test.dsl", diag);
        Parser parser(lex.tokenize(), diag);
        auto prog = parser.parse_program();
        auto plan = lowerer.lower(*prog->statements[0]);

        CHECK(SbomUtilityCodeGen::can_offload(plan));
        auto cmd = SbomUtilityCodeGen::generate_command(plan, "bom.json");
        REQUIRE(cmd.has_value());
        CHECK(*cmd == "sbom-utility query --input-file \"bom.json\" --from components --select name,version --where \"type=library\"");
    }

    SUBCASE("Non-mappable query (WHO USES contains graph traversal)") {
        Lexer lex("WHO USES 'express';", "test.dsl", diag);
        Parser parser(lex.tokenize(), diag);
        auto prog = parser.parse_program();
        auto plan = lowerer.lower(*prog->statements[0]);

        std::string reason;
        CHECK_FALSE(SbomUtilityCodeGen::can_offload(plan, &reason));
        CHECK_FALSE(reason.empty());
    }

    SUBCASE("Non-mappable query (LIKE operator)") {
        Lexer lex("SELECT name FROM components WHERE name LIKE 'log%';", "test.dsl", diag);
        Parser parser(lex.tokenize(), diag);
        auto prog = parser.parse_program();
        auto plan = lowerer.lower(*prog->statements[0]);

        std::string reason;
        CHECK_FALSE(SbomUtilityCodeGen::can_offload(plan, &reason));
        CHECK(reason.find("LIKE") != std::string::npos);
    }
}

TEST_CASE("Backend: Pattern Matching (LIKE, CONTAINS, MATCHES)") {
    SUBCASE("LIKE with prefix wildcard 'log%'") {
        auto res = run_query("SELECT name FROM components WHERE name LIKE 'log%';");
        CHECK_FALSE(res.is_empty());
        REQUIRE(res.rows.size() == 1);
        CHECK(res.rows[0][0] == "log4j-core");
    }

    SUBCASE("LIKE with suffix wildcard '%parser'") {
        auto res = run_query("SELECT name FROM components WHERE name LIKE '%parser';");
        CHECK_FALSE(res.is_empty());
        REQUIRE(res.rows.size() == 1);
        CHECK(res.rows[0][0] == "body-parser");
    }

    SUBCASE("LIKE with single character wildcard 'lo_ash'") {
        auto res = run_query("SELECT name FROM components WHERE name LIKE 'lo_ash';");
        CHECK_FALSE(res.is_empty());
        REQUIRE(res.rows.size() == 1);
        CHECK(res.rows[0][0] == "lodash");
    }

    SUBCASE("LIKE exact match without wildcards") {
        auto res = run_query("SELECT name FROM components WHERE name LIKE 'express';");
        CHECK_FALSE(res.is_empty());
        REQUIRE(res.rows.size() == 1);
        CHECK(res.rows[0][0] == "express");
    }

    SUBCASE("CONTAINS substring matching (case-insensitive)") {
        // 'maven' in purl -> log4j-core
        auto res_maven = run_query("SELECT name FROM components WHERE purl CONTAINS 'maven';");
        REQUIRE(res_maven.rows.size() == 1);
        CHECK(res_maven.rows[0][0] == "log4j-core");

        // 'NPM' (uppercase) in purl -> express, body-parser, qs, lodash (4 libraries)
        auto res_npm = run_query("SELECT name FROM components WHERE purl CONTAINS 'NPM';");
        CHECK(res_npm.rows.size() == 4);
    }

    SUBCASE("MATCHES regular expression") {
        auto res = run_query("SELECT id FROM vulnerabilities WHERE description MATCHES 'JNDI.*LDAP';");
        CHECK_FALSE(res.is_empty());
        REQUIRE(res.rows.size() == 1);
        CHECK(res.rows[0][0] == "CVE-2021-44228");
    }

    SUBCASE("LIKE with package url prefix 'pkg:npm%'") {
        auto res = run_query("SELECT name FROM components WHERE purl LIKE 'pkg:npm%';");
        CHECK_FALSE(res.is_empty());
        CHECK(res.rows.size() == 4); // express, body-parser, qs, lodash
    }

    SUBCASE("Reversed operands: literal on LHS, column on RHS") {
        auto res_eq = run_query("SELECT name FROM components WHERE 'express' = name;");
        REQUIRE(res_eq.rows.size() == 1);
        CHECK(res_eq.rows[0][0] == "express");

        auto res_num = run_query("SELECT id FROM vulnerabilities WHERE 8.0 <= score;");
        REQUIRE(res_num.rows.size() == 1);
        CHECK(res_num.rows[0][0] == "CVE-2021-44228");
    }
}

TEST_CASE("Backend: Result Formatter (Table, JSON, Tree, DOT, Mermaid)") {
    QueryResult res;
    res.columns = {"name", "version"};
    res.rows = {{"express", "4.17.1"}, {"lodash", "4.17.21"}};

    SUBCASE("Table output format") {
        std::string table = ResultFormatter::to_table(res);
        CHECK(table.find("express") != std::string::npos);
        CHECK(table.find("4.17.1") != std::string::npos);
    }

    SUBCASE("JSON output format") {
        std::string json = ResultFormatter::to_json(res);
        CHECK(json.find("\"name\": \"express\"") != std::string::npos);
    }

    SUBCASE("Graphviz DOT export for SHOW TREE") {
        auto res_tree = run_query("SHOW TREE OF 'my-web-app' DEPTH 2;");
        std::string dot = ResultFormatter::to_dot(res_tree);

        // Verify Graphviz syntax and header
        CHECK(dot.find("digraph") != std::string::npos);
        CHECK(dot.find("rankdir=TB;") != std::string::npos);

        // Verify nodes
        CHECK(dot.find("\"my-web-app\"") != std::string::npos);
        CHECK(dot.find("\"express\"") != std::string::npos);
        CHECK(dot.find("\"log4j-core\"") != std::string::npos);
        CHECK(dot.find("\"body-parser\"") != std::string::npos);

        // Verify edges
        CHECK(dot.find("\"my-web-app\" -> \"express\"") != std::string::npos);
        CHECK(dot.find("\"my-web-app\" -> \"log4j-core\"") != std::string::npos);
        CHECK(dot.find("\"express\" -> \"body-parser\"") != std::string::npos);

        // Verify semantic coloration
        CHECK(dot.find("#2e78d2") != std::string::npos); // root application
        CHECK(dot.find("#ff4d4d") != std::string::npos); // vulnerable node (log4j-core)
        CHECK(dot.find("#e1f5fe") != std::string::npos); // standard dependencies
    }

    SUBCASE("Mermaid export for FIND BLAST RADIUS") {
        auto res_blast = run_query("FIND BLAST RADIUS OF 'CVE-2022-29244';");
        std::string mermaid = ResultFormatter::to_mermaid(res_blast);

        // Verify Mermaid syntax and header
        CHECK(mermaid.find("graph TD") != std::string::npos);

        // Verify nodes
        CHECK(mermaid.find("qs") != std::string::npos);
        CHECK(mermaid.find("body_parser") != std::string::npos);
        CHECK(mermaid.find("express") != std::string::npos);
        CHECK(mermaid.find("my_web_app") != std::string::npos);

        // Verify edges
        CHECK(mermaid.find("my_web_app --> express") != std::string::npos);
        CHECK(mermaid.find("express --> body_parser") != std::string::npos);
        CHECK(mermaid.find("body_parser --> qs") != std::string::npos);

        // Verify semantic security coloration
        CHECK(mermaid.find("style qs fill:#ff4d4d") != std::string::npos); // vulnerable target
        CHECK(mermaid.find("style body_parser fill:#ffa500") != std::string::npos); // transitive impact
        CHECK(mermaid.find("style express fill:#ffa500") != std::string::npos); // transitive impact
        CHECK(mermaid.find("style my_web_app fill:#2e78d2") != std::string::npos); // root application
    }

    SUBCASE("Cross-format: SHOW TREE with Mermaid and BLAST RADIUS with DOT") {
        auto res_tree = run_query("SHOW TREE OF 'my-web-app' DEPTH 2;");
        std::string tree_mermaid = ResultFormatter::to_mermaid(res_tree);
        CHECK(tree_mermaid.find("graph TD") != std::string::npos);
        CHECK(tree_mermaid.find("my_web_app --> express") != std::string::npos);
        CHECK(tree_mermaid.find("style log4j_core fill:#ff4d4d") != std::string::npos);

        auto res_blast = run_query("FIND BLAST RADIUS OF 'CVE-2022-29244';");
        std::string blast_dot = ResultFormatter::to_dot(res_blast);
        CHECK(blast_dot.find("digraph") != std::string::npos);
        CHECK(blast_dot.find("\"my-web-app\" -> \"express\"") != std::string::npos);
        CHECK(blast_dot.find("\"qs\"") != std::string::npos);
        CHECK(blast_dot.find("#ff4d4d") != std::string::npos);
        CHECK(blast_dot.find("#ffa500") != std::string::npos);
    }

    SUBCASE("Direct Formatter with custom GraphData and empty results") {
        QueryResult custom_res;
        GraphData gd;
        gd.title = "CustomGraph";
        gd.nodes.push_back({"app", "my-app", "1.0.0", "root", "", 0});
        gd.nodes.push_back({"lib", "vuln-lib", "0.9.1", "vulnerable", "CVE-2020-0001", 1});
        gd.edges.push_back({"app", "lib", "depends"});
        custom_res.graph = gd;

        std::string dot = ResultFormatter::format(custom_res, OutputFormat::Dot);
        CHECK(dot.find("digraph CustomGraph") != std::string::npos);
        CHECK(dot.find("\"app\" -> \"lib\"") != std::string::npos);

        std::string mermaid = ResultFormatter::format(custom_res, OutputFormat::Mermaid);
        CHECK(mermaid.find("graph TD") != std::string::npos);
        CHECK(mermaid.find("my_app -->|depends| vuln_lib") != std::string::npos);

        QueryResult empty_res;
        CHECK(ResultFormatter::to_dot(empty_res).find("digraph") != std::string::npos);
        CHECK(ResultFormatter::to_mermaid(empty_res).find("graph TD") != std::string::npos);
    }
}

TEST_CASE("Backend: Functional Equivalence with IROptimizer") {
    SUBCASE("SELECT components with constant tautology WHERE 1 = 1") {
        std::string q = "SELECT name, version FROM components WHERE 1 = 1 AND type = 'library' ORDER BY name ASC;";
        auto res_opt = run_optimized_query(q);
        auto res_unopt = run_query(q);

        CHECK_FALSE(res_opt.is_empty());
        CHECK(res_opt.columns == res_unopt.columns);
        CHECK(res_opt.rows == res_unopt.rows);
        CHECK(res_opt.rows.size() == 5);
        CHECK(res_opt.rows[0][0] == "body-parser");
        CHECK(res_opt.rows[1][0] == "express");
        CHECK(res_opt.rows[2][0] == "lodash");
        CHECK(res_opt.rows[3][0] == "log4j-core");
        CHECK(res_opt.rows[4][0] == "qs");
    }

    SUBCASE("WHERE 1 = 0 produces empty result in both plans") {
        std::string q = "SELECT name FROM components WHERE 1 = 0;";
        auto res_opt = run_optimized_query(q);
        auto res_unopt = run_query(q);

        CHECK(res_opt.rows.empty());
        CHECK(res_unopt.rows.empty());
    }

    SUBCASE("Pushed-down join predicate on component name") {
        std::string q = "FIND VULNERABLE LIBRARIES SEVERITY >= HIGH WHERE name = 'log4j-core';";
        auto res_opt = run_optimized_query(q);
        auto res_unopt = run_query(q);

        CHECK_FALSE(res_opt.is_empty());
        CHECK(res_opt.rows.size() == 1);
        CHECK(res_opt.rows[0][0] == "log4j-core");
        CHECK(res_opt.rows == res_unopt.rows);
    }

    SUBCASE("Pushed-down join predicate on vulnerability cwe") {
        std::string q = "FIND VULNERABLE LIBRARIES SEVERITY >= HIGH WHERE cwe = 502;";
        auto res_opt = run_optimized_query(q);
        auto res_unopt = run_query(q);

        CHECK_FALSE(res_opt.is_empty());
        CHECK(res_opt.rows.size() == 1);
        CHECK(res_opt.rows[0][0] == "log4j-core");
        CHECK(res_opt.rows == res_unopt.rows);
    }

    SUBCASE("Full functional equivalence across multiple query types") {
        std::vector<std::string> queries = {
            "SELECT name FROM components ORDER BY name ASC;",
            "SELECT name, version FROM components WHERE type = 'library';",
            "WHO USES 'qs' TRANSITIVE;",
            "SHOW TREE OF 'my-web-app' DEPTH 2;",
            "FIND BLAST RADIUS OF 'CVE-2022-29244';",
            "SELECT name FROM components WHERE 1 = 1 AND (name LIKE 'exp%' OR name = 'lodash');",
            "ASSERT NO VULNERABILITIES SEVERITY > 10.0;",
            "ASSERT NO COMPONENTS WHERE type = 'framework';"
        };

        for (const auto& q : queries) {
            auto res_unopt = run_query(q);
            auto res_opt = run_optimized_query(q);

            CHECK(res_unopt.columns == res_opt.columns);
            CHECK(res_unopt.rows == res_opt.rows);
            CHECK(res_unopt.is_assertion == res_opt.is_assertion);
            CHECK(res_unopt.assertion_passed == res_opt.assertion_passed);
        }
    }
}

