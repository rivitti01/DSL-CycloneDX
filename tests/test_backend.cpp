#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "sbom_dsl/lexer/lexer.hpp"
#include "sbom_dsl/parser/parser.hpp"
#include "sbom_dsl/lowering/query_lowerer.hpp"
#include "sbom_dsl/backend/native_engine.hpp"
#include "sbom_dsl/backend/sbom_utility_codegen.hpp"
#include "sbom_dsl/backend/result_formatter.hpp"

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
}

TEST_CASE("Backend: Result Formatter") {
    QueryResult res;
    res.columns = {"name", "version"};
    res.rows = {{"express", "4.17.1"}, {"lodash", "4.17.21"}};

    std::string table = ResultFormatter::to_table(res);
    CHECK(table.find("express") != std::string::npos);
    CHECK(table.find("4.17.1") != std::string::npos);

    std::string json = ResultFormatter::to_json(res);
    CHECK(json.find("\"name\": \"express\"") != std::string::npos);
}
