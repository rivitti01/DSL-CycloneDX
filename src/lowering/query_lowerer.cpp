#include "sbom_dsl/lowering/query_lowerer.hpp"
#include "sbom_dsl/ir/ir_optimizer.hpp"
#include <stdexcept>
#include <sstream>

namespace sbom_dsl {

std::unique_ptr<ExpressionNode> QueryLowerer::clone_expression(const ExpressionNode* expr) {
    return sbom_dsl::clone_expression(expr);
}

IRPlan QueryLowerer::lower(StatementNode& statement) {
    if (auto* sel = dynamic_cast<SelectStatement*>(&statement)) {
        return lower_select(*sel);
    }
    if (auto* who = dynamic_cast<WhoUsesStatement*>(&statement)) {
        return lower_who_uses(*who);
    }
    if (auto* find = dynamic_cast<FindVulnerableStatement*>(&statement)) {
        return lower_find_vulnerable(*find);
    }
    if (auto* tree = dynamic_cast<ShowTreeStatement*>(&statement)) {
        return lower_show_tree(*tree);
    }
    if (auto* blast = dynamic_cast<BlastRadiusStatement*>(&statement)) {
        return lower_blast_radius(*blast);
    }
    if (auto* asrt = dynamic_cast<AssertStatement*>(&statement)) {
        return lower_assert(*asrt);
    }
    throw std::runtime_error("Unknown statement type in QueryLowerer");
}

IRPlan QueryLowerer::lower_select(SelectStatement& stmt) {
    IRPlan plan;
    plan.bom_path = stmt.bom_path;

    std::unique_ptr<IRNode> root = std::make_unique<IRScan>(stmt.collection, stmt.bom_path);

    if (stmt.where_clause) {
        root = std::make_unique<IRFilter>(std::move(root), clone_expression(stmt.where_clause.get()));
    }

    if (stmt.order_by) {
        root = std::make_unique<IRSort>(std::move(root), stmt.order_by->column, stmt.order_by->ascending);
    }

    if (stmt.limit) {
        root = std::make_unique<IRLimit>(std::move(root), *stmt.limit);
    }

    root = std::make_unique<IRProject>(std::move(root), stmt.projections);
    plan.root = std::move(root);
    return plan;
}

IRPlan QueryLowerer::lower_who_uses(WhoUsesStatement& stmt) {
    IRPlan plan;
    plan.bom_path = stmt.bom_path;

    // 1. Scan dependencies
    auto dep_scan = std::make_unique<IRScan>("dependencies", stmt.bom_path);

    // 2. Reverse graph traversal to find all ancestors depending on target
    auto traverse = std::make_unique<IRGraphTraverse>(
        std::move(dep_scan),
        stmt.target_component,
        GraphDirection::Reverse,
        stmt.is_transitive
    );

    // 3. Hash join with components to resolve component names, versions, and types
    auto comp_scan = std::make_unique<IRScan>("components", stmt.bom_path);
    auto join = std::make_unique<IRHashJoin>(
        std::move(traverse),
        std::move(comp_scan),
        "ref",
        "bom-ref"
    );

    // 4. Project key attributes
    std::vector<std::string> proj = {"name", "version", "type", "bom-ref", "purl"};
    plan.root = std::make_unique<IRProject>(std::move(join), proj);
    return plan;
}

IRPlan QueryLowerer::lower_find_vulnerable(FindVulnerableStatement& stmt) {
    IRPlan plan;
    plan.bom_path = stmt.bom_path;

    // 1. Scan vulnerabilities
    std::unique_ptr<IRNode> vuln_pipeline = std::make_unique<IRScan>("vulnerabilities", stmt.bom_path);

    // If severity filter specified: e.g. severity >= HIGH
    if (stmt.severity_level) {
        auto col = std::make_unique<ColumnRefExpr>(std::vector<std::string>{"ratings", "severity"}, stmt.location);
        auto lit = std::make_unique<LiteralExpr>(*stmt.severity_level, stmt.location);
        BinaryOperator op = stmt.severity_op.value_or(BinaryOperator::Equal);
        auto sev_pred = std::make_unique<BinaryOpExpr>(op, std::move(col), std::move(lit), stmt.location);

        vuln_pipeline = std::make_unique<IRFilter>(std::move(vuln_pipeline), std::move(sev_pred));
    }

    // 2. Scan components
    std::unique_ptr<IRNode> comp_pipeline = std::make_unique<IRScan>("components", stmt.bom_path);
    if (stmt.libraries_only) {
        auto col = std::make_unique<ColumnRefExpr>(std::vector<std::string>{"type"}, stmt.location);
        auto lit = std::make_unique<LiteralExpr>(std::string("library"), stmt.location);
        auto type_pred = std::make_unique<BinaryOpExpr>(BinaryOperator::Equal, std::move(col), std::move(lit), stmt.location);

        comp_pipeline = std::make_unique<IRFilter>(std::move(comp_pipeline), std::move(type_pred));
    }

    // 3. Hash Join on affects == bom-ref
    auto join = std::make_unique<IRHashJoin>(
        std::move(vuln_pipeline),
        std::move(comp_pipeline),
        "affects",
        "bom-ref"
    );

    std::unique_ptr<IRNode> root = std::move(join);

    // Additional where clause on joined relation in unoptimized IR (to be pushed down by IROptimizer)
    if (stmt.where_clause) {
        root = std::make_unique<IRFilter>(std::move(root), clone_expression(stmt.where_clause.get()));
    }

    // 4. Project
    std::vector<std::string> proj = {"name", "version", "type", "vuln_id", "severity", "score", "description"};
    plan.root = std::make_unique<IRProject>(std::move(root), proj);
    return plan;
}

IRPlan QueryLowerer::lower_show_tree(ShowTreeStatement& stmt) {
    IRPlan plan;
    plan.bom_path = stmt.bom_path;

    auto dep_scan = std::make_unique<IRScan>("dependencies", stmt.bom_path);
    std::string root_target = stmt.root_component.value_or("");

    auto traverse = std::make_unique<IRGraphTraverse>(
        std::move(dep_scan),
        root_target,
        GraphDirection::Forward,
        true,
        stmt.max_depth
    );

    auto comp_scan = std::make_unique<IRScan>("components", stmt.bom_path);
    auto join = std::make_unique<IRHashJoin>(
        std::move(traverse),
        std::move(comp_scan),
        "ref",
        "bom-ref"
    );

    std::vector<std::string> proj = {"name", "version", "depth", "bom-ref"};
    plan.root = std::make_unique<IRProject>(std::move(join), proj);
    return plan;
}

IRPlan QueryLowerer::lower_blast_radius(BlastRadiusStatement& stmt) {
    IRPlan plan;
    plan.bom_path = stmt.bom_path;

    auto vuln_scan = std::make_unique<IRScan>("vulnerabilities", stmt.bom_path);
    auto blast = std::make_unique<IRBlastRadius>(std::move(vuln_scan), stmt.vulnerability_id);

    plan.root = std::move(blast);
    return plan;
}

IRPlan QueryLowerer::lower_assert(AssertStatement& stmt) {
    IRPlan plan;
    plan.bom_path = stmt.bom_path;
    plan.is_assertion = true;

    if (stmt.target == AssertTarget::Vulnerabilities) {
        std::string title = "ASSERT NO VULNERABILITIES";
        if (stmt.severity_level) {
            title += " SEVERITY " +
                std::string(stmt.severity_op ? binary_op_to_string(*stmt.severity_op) : "=") + " " +
                std::string(severity_to_string(*stmt.severity_level));
        } else if (stmt.score_threshold) {
            std::ostringstream ss;
            ss << *stmt.score_threshold;
            title += " SEVERITY " +
                std::string(stmt.severity_op ? binary_op_to_string(*stmt.severity_op) : "=") + " " +
                ss.str();
        }
        plan.assertion_title = title;

        // 1. Scan vulnerabilities
        std::unique_ptr<IRNode> vuln_pipeline = std::make_unique<IRScan>("vulnerabilities", stmt.bom_path);

        if (stmt.severity_level) {
            auto col = std::make_unique<ColumnRefExpr>(std::vector<std::string>{"ratings", "severity"}, stmt.location);
            auto lit = std::make_unique<LiteralExpr>(*stmt.severity_level, stmt.location);
            BinaryOperator op = stmt.severity_op.value_or(BinaryOperator::Equal);
            auto sev_pred = std::make_unique<BinaryOpExpr>(op, std::move(col), std::move(lit), stmt.location);
            vuln_pipeline = std::make_unique<IRFilter>(std::move(vuln_pipeline), std::move(sev_pred));
        } else if (stmt.score_threshold) {
            auto col = std::make_unique<ColumnRefExpr>(std::vector<std::string>{"ratings", "score"}, stmt.location);
            auto lit = std::make_unique<LiteralExpr>(*stmt.score_threshold, stmt.location);
            BinaryOperator op = stmt.severity_op.value_or(BinaryOperator::Equal);
            auto score_pred = std::make_unique<BinaryOpExpr>(op, std::move(col), std::move(lit), stmt.location);
            vuln_pipeline = std::make_unique<IRFilter>(std::move(vuln_pipeline), std::move(score_pred));
        }

        // 2. Scan components
        std::unique_ptr<IRNode> comp_pipeline = std::make_unique<IRScan>("components", stmt.bom_path);

        // 3. Hash Join on affects == bom-ref
        auto join = std::make_unique<IRHashJoin>(
            std::move(vuln_pipeline),
            std::move(comp_pipeline),
            "affects",
            "bom-ref"
        );

        std::unique_ptr<IRNode> root = std::move(join);

        if (stmt.where_clause) {
            root = std::make_unique<IRFilter>(std::move(root), clone_expression(stmt.where_clause.get()));
        }

        // 4. Project
        std::vector<std::string> proj = {"name", "version", "type", "vuln_id", "severity", "score", "description"};
        plan.root = std::make_unique<IRProject>(std::move(root), proj);
    } else {
        bool is_lib = (stmt.target == AssertTarget::Libraries);
        plan.assertion_title = is_lib ? "ASSERT NO LIBRARIES" : "ASSERT NO COMPONENTS";

        std::unique_ptr<IRNode> root = std::make_unique<IRScan>("components", stmt.bom_path);

        if (is_lib) {
            auto col = std::make_unique<ColumnRefExpr>(std::vector<std::string>{"type"}, stmt.location);
            auto lit = std::make_unique<LiteralExpr>(std::string("library"), stmt.location);
            auto type_pred = std::make_unique<BinaryOpExpr>(BinaryOperator::Equal, std::move(col), std::move(lit), stmt.location);
            root = std::make_unique<IRFilter>(std::move(root), std::move(type_pred));
        }

        if (stmt.where_clause) {
            root = std::make_unique<IRFilter>(std::move(root), clone_expression(stmt.where_clause.get()));
        }

        std::vector<std::string> proj = {"name", "version", "type", "purl"};
        plan.root = std::make_unique<IRProject>(std::move(root), proj);
    }

    return plan;
}

} // namespace sbom_dsl
