#pragma once

#include "sbom_dsl/ast/ast_visitor.hpp"
#include "sbom_dsl/ast/ast.hpp"
#include "sbom_dsl/common/diagnostic.hpp"
#include "sbom_dsl/semantic/schema_catalog.hpp"

namespace sbom_dsl {

class TypeChecker : public ASTVisitor {
public:
    explicit TypeChecker(DiagnosticEngine& diag);

    bool check(ASTNode& node);

    void visit(ProgramNode& node) override;
    void visit(SelectStatement& node) override;
    void visit(WhoUsesStatement& node) override;
    void visit(FindVulnerableStatement& node) override;
    void visit(ShowTreeStatement& node) override;
    void visit(BlastRadiusStatement& node) override;

    void visit(BinaryOpExpr& node) override;
    void visit(UnaryOpExpr& node) override;
    void visit(ColumnRefExpr& node) override;
    void visit(LiteralExpr& node) override;

private:
    DataType infer_expression_type(ExpressionNode& expr);
    bool are_types_compatible(DataType t1, DataType t2, BinaryOperator op) const;

    DiagnosticEngine& diag_;
    SchemaCatalog& catalog_;
    std::string current_collection_;
    DataType last_inferred_type_{DataType::Unknown};
};

} // namespace sbom_dsl
