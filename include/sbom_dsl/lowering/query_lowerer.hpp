#pragma once

#include "sbom_dsl/ast/ast.hpp"
#include "sbom_dsl/ir/ir.hpp"
#include <memory>

namespace sbom_dsl {

class QueryLowerer {
public:
    IRPlan lower(StatementNode& statement);

    IRPlan lower_select(SelectStatement& stmt);
    IRPlan lower_who_uses(WhoUsesStatement& stmt);
    IRPlan lower_find_vulnerable(FindVulnerableStatement& stmt);
    IRPlan lower_show_tree(ShowTreeStatement& stmt);
    IRPlan lower_blast_radius(BlastRadiusStatement& stmt);

private:
    std::unique_ptr<ExpressionNode> clone_expression(const ExpressionNode* expr);
};

} // namespace sbom_dsl
