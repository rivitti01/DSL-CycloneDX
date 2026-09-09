#pragma once

#include "sbom_dsl/ast/ast.hpp"
#include "sbom_dsl/ast/ast_visitor.hpp"
#include <string>
#include <sstream>

namespace sbom_dsl {

class ASTPrinter : public ASTVisitor {
public:
    std::string print(ASTNode& node);

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
    void indent();
    void dedent();
    void write_indent();

    std::ostringstream oss_;
    int indent_level_{0};
};

} // namespace sbom_dsl
