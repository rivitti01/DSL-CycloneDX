#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include <doctest/doctest.h>
#include "sbom_dsl/lexer/lexer.hpp"
#include "sbom_dsl/parser/parser.hpp"
#include "sbom_dsl/semantic/type_checker.hpp"
#include "sbom_dsl/lowering/query_lowerer.hpp"
#include "sbom_dsl/backend/native_engine.hpp"
#include <cstdlib>

using namespace sbom_dsl;

static const std::string FIXTURE = std::string(TEST_FIXTURE_DIR) + "/sample_cyclonedx.json";

TEST_CASE("End-to-End: Full Compiler Pipeline") {
    DiagnosticEngine diag;
    NativeEngine engine;
    bool loaded = engine.load_bom_file(FIXTURE, diag);
    REQUIRE(loaded);

    auto run_e2e = [&](const std::string& source) -> QueryResult {
        Lexer lexer(source, "e2e.dsl", diag);
        auto tokens = lexer.tokenize();
        REQUIRE_FALSE(diag.has_errors());

        Parser parser(std::move(tokens), diag);
        auto prog = parser.parse_program();
        REQUIRE_FALSE(diag.has_errors());
        REQUIRE(prog != nullptr);
        REQUIRE(prog->statements.size() == 1);

        TypeChecker checker(diag);
        bool ok = checker.check(*prog);
        REQUIRE(ok);

        QueryLowerer lowerer;
        auto plan = lowerer.lower(*prog->statements[0]);

        return engine.execute(plan, diag);
    };

    SUBCASE("Complex boolean WHERE clause") {
        std::string q = "SELECT name FROM components WHERE type = 'library' AND (name = 'express' OR name = 'lodash');";
        auto res = run_e2e(q);
        CHECK_FALSE(res.is_empty());
        CHECK(res.rows.size() == 2);
    }

    SUBCASE("Direct WHO USES vs Transitive WHO USES") {
        // Direct users of qs: only body-parser
        auto res_direct = run_e2e("WHO USES 'qs' DIRECT;");
        CHECK(res_direct.rows.size() == 1);
        CHECK(res_direct.rows[0][0] == "body-parser");

        // Transitive users of qs: body-parser, express, my-web-app
        auto res_trans = run_e2e("WHO USES 'qs' TRANSITIVE;");
        CHECK(res_trans.rows.size() == 3);
    }

    SUBCASE("Severity threshold: CRITICAL vs HIGH") {
        // Only log4j-core has CRITICAL (10.0)
        auto res_crit = run_e2e("FIND VULNERABLE LIBRARIES SEVERITY >= CRITICAL;");
        REQUIRE(res_crit.rows.size() == 1);
        CHECK(res_crit.rows[0][0] == "log4j-core");

        // Both log4j-core (CRITICAL) and qs (HIGH) match >= HIGH
        auto res_high = run_e2e("FIND VULNERABLE LIBRARIES SEVERITY >= HIGH;");
        CHECK(res_high.rows.size() == 2);
    }

    SUBCASE("SHOW TREE depth limit") {
        // Under my-web-app: depth 1 has 2 components (express, log4j-core)
        auto res_depth1 = run_e2e("SHOW TREE OF 'my-web-app' DEPTH 1;");
        CHECK(res_depth1.rows.size() == 2);

        // depth 2 adds body-parser
        auto res_depth2 = run_e2e("SHOW TREE OF 'my-web-app' DEPTH 2;");
        CHECK(res_depth2.rows.size() == 3);
    }

    SUBCASE("Blast Radius calculation") {
        auto res_blast = run_e2e("FIND BLAST RADIUS OF 'CVE-2021-44228';");
        REQUIRE(res_blast.blast_radius.has_value());
        // log4j-core is directly used by my-web-app
        CHECK(res_blast.blast_radius->directly_affected_components == 1);
        CHECK(res_blast.blast_radius->transitively_affected_components == 2); // log4j-core + my-web-app
        CHECK(res_blast.blast_radius->root_application_affected == true);
    }

    SUBCASE("Pattern matching with LIKE and CONTAINS") {
        std::string q = "SELECT name, version FROM components WHERE (name LIKE 'log%' OR name LIKE 'exp%') AND purl CONTAINS 'pkg:' ORDER BY name ASC;";
        auto res = run_e2e(q);
        CHECK_FALSE(res.is_empty());
        REQUIRE(res.rows.size() == 2);
        CHECK(res.rows[0][0] == "express");
        CHECK(res.rows[0][1] == "4.17.1");
        CHECK(res.rows[1][0] == "log4j-core");
        CHECK(res.rows[1][1] == "2.14.1");
    }

    SUBCASE("Policy Gatekeeper: ASSERT NO VULNERABILITIES pass and fail") {
        // Assert passing: score > 10.0 (no vulnerability has CVSS score > 10.0)
        auto res_pass = run_e2e("ASSERT NO VULNERABILITIES SEVERITY > 10.0;");
        CHECK(res_pass.is_assertion);
        CHECK(res_pass.assertion_passed);
        CHECK(res_pass.rows.empty());

        // Assert failing: SEVERITY >= HIGH matches log4j-core (CRITICAL, score 10.0) and qs (HIGH, score 7.5)
        auto res_fail = run_e2e("ASSERT NO VULNERABILITIES SEVERITY >= HIGH;");
        CHECK(res_fail.is_assertion);
        CHECK_FALSE(res_fail.assertion_passed);
        CHECK(res_fail.rows.size() == 2);
        CHECK(res_fail.rows[0][0] == "log4j-core");
        CHECK(res_fail.rows[1][0] == "qs");

        // Assert failing with level: SEVERITY = CRITICAL matches log4j-core
        auto res_crit = run_e2e("ASSERT NO VULNERABILITIES SEVERITY = CRITICAL;");
        CHECK(res_crit.is_assertion);
        CHECK_FALSE(res_crit.assertion_passed);
        CHECK(res_crit.rows.size() == 1);
        CHECK(res_crit.rows[0][0] == "log4j-core");
    }

    SUBCASE("Policy Gatekeeper: ASSERT NO COMPONENTS / LIBRARIES") {
        // Passing: no framework components in fixture
        auto res_comp_pass = run_e2e("ASSERT NO COMPONENTS WHERE type = 'framework';");
        CHECK(res_comp_pass.is_assertion);
        CHECK(res_comp_pass.assertion_passed);
        CHECK(res_comp_pass.rows.empty());

        // Failing: library express exists
        auto res_comp_fail = run_e2e("ASSERT NO COMPONENTS WHERE name = 'express';");
        CHECK(res_comp_fail.is_assertion);
        CHECK_FALSE(res_comp_fail.assertion_passed);
        CHECK(res_comp_fail.rows.size() == 1);
        CHECK(res_comp_fail.rows[0][0] == "express");

        // Passing with LIBRARIES: no library named 'my-web-app' (my-web-app is an application)
        auto res_lib_pass = run_e2e("ASSERT NO LIBRARIES WHERE name = 'my-web-app';");
        CHECK(res_lib_pass.is_assertion);
        CHECK(res_lib_pass.assertion_passed);
        CHECK(res_lib_pass.rows.empty());
    }

    SUBCASE("CLI Gatekeeper exit codes (0 on compliance, 1 on violation)") {
        std::string exe = "./sbom-dsl";
        if (std::ifstream("./build/sbom-dsl").good()) {
            exe = "./build/sbom-dsl";
        }

        // Run passing query
        std::string cmd_pass = exe + " -b \"" + FIXTURE + "\" -c \"ASSERT NO VULNERABILITIES SEVERITY > 10.0;\" > /dev/null 2>&1";
        int ret_pass = std::system(cmd_pass.c_str());
        CHECK(ret_pass == 0);

        // Run failing query
        std::string cmd_fail = exe + " -b \"" + FIXTURE + "\" -c \"ASSERT NO VULNERABILITIES SEVERITY >= HIGH;\" > /dev/null 2>&1";
        int ret_fail = std::system(cmd_fail.c_str());
        int exit_code = (ret_fail >= 0 && ret_fail <= 255) ? ret_fail : (ret_fail >> 8);
        CHECK(exit_code == 1);
    }
}
