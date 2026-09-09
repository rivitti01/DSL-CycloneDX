#pragma once

#include "sbom_dsl/ir/ir.hpp"
#include "sbom_dsl/ast/ast.hpp"
#include <memory>
#include <vector>
#include <string>
#include <unordered_set>

namespace sbom_dsl {

// Deep cloning utilities for IR and expressions
std::unique_ptr<ExpressionNode> clone_expression(const ExpressionNode* expr);
std::unique_ptr<IRNode> clone_ir_node(const IRNode* node);
IRPlan clone_ir_plan(const IRPlan& plan);

// Relational algebraic analysis utilities
std::vector<std::unique_ptr<ExpressionNode>> split_conjunction(const ExpressionNode* expr);
std::unique_ptr<ExpressionNode> combine_conjunction(std::vector<std::unique_ptr<ExpressionNode>> conjuncts, SourceLocation loc = SourceLocation{});
std::unordered_set<std::string> get_referenced_columns(const ExpressionNode& expr);
std::unordered_set<std::string> get_produced_attributes(const IRNode& node);

class IROptimizer {
public:
    IROptimizer() = default;

    // Main entrypoint: optimizes an entire execution plan by applying constant folding,
    // predicate pushdown, and redundant filter elimination.
    IRPlan optimize(const IRPlan& plan);

    // Tree-level optimization passes
    std::unique_ptr<IRNode> optimize_node(std::unique_ptr<IRNode> node);
    std::unique_ptr<IRNode> fold_constants(std::unique_ptr<IRNode> node);
    std::unique_ptr<IRNode> pushdown_predicates(std::unique_ptr<IRNode> node);

    // Expression-level constant folding and boolean identity simplification
    std::unique_ptr<ExpressionNode> fold_expression(std::unique_ptr<ExpressionNode> expr);

    // Check if an expression simplifies to a constant boolean literal
    static bool is_true_literal(const ExpressionNode* expr);
    static bool is_false_literal(const ExpressionNode* expr);

private:
    std::unique_ptr<ExpressionNode> evaluate_binary_literals(
        BinaryOperator op,
        const LiteralExpr& left,
        const LiteralExpr& right,
        SourceLocation loc
    );
};

} // namespace sbom_dsl
