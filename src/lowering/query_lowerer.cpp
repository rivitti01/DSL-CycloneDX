#include "sbom_dsl/lowering/query_lowerer.hpp"
#include <stdexcept>

namespace sbom_dsl {

std::unique_ptr<ExpressionNode> QueryLowerer::clone_expression(const ExpressionNode* expr) {
    if (!expr) return nullptr;

    if (const auto* bin = dynamic_cast<const BinaryOpExpr*>(expr)) {
        return std::make_unique<BinaryOpExpr>(
            bin->op,
            clone_expression(bin->left.get()),
            clone_expression(bin->right.get()),
            bin->location
        );
    }
    if (const auto* un = dynamic_cast<const UnaryOpExpr*>(expr)) {
        return std::make_unique<UnaryOpExpr>(
            un->op,
            clone_expression(un->operand.get()),
            un->location
        );
    }
    if (const auto* col = dynamic_cast<const ColumnRefExpr*>(expr)) {
        return std::make_unique<ColumnRefExpr>(col->path, col->location);
    }
    if (const auto* lit = dynamic_cast<const LiteralExpr*>(expr)) {
        return std::make_unique<LiteralExpr>(lit->value, lit->location);
    }
    return nullptr;
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

    // Additional where clause
    if (stmt.where_clause) {
        vuln_pipeline = std::make_unique<IRFilter>(std::move(vuln_pipeline), clone_expression(stmt.where_clause.get()));
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

    // 4. Project
    std::vector<std::string> proj = {"name", "version", "type", "vuln_id", "severity", "score", "description"};
    plan.root = std::make_unique<IRProject>(std::move(join), proj);
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

} // namespace sbom_dsl
