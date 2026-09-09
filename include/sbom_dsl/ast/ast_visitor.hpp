#pragma once

namespace sbom_dsl {

class ProgramNode;
class SelectStatement;
class WhoUsesStatement;
class FindVulnerableStatement;
class ShowTreeStatement;
class BlastRadiusStatement;
class BinaryOpExpr;
class UnaryOpExpr;
class ColumnRefExpr;
class LiteralExpr;

class ASTVisitor {
public:
    virtual ~ASTVisitor() = default;

    virtual void visit(ProgramNode& node) = 0;
    virtual void visit(SelectStatement& node) = 0;
    virtual void visit(WhoUsesStatement& node) = 0;
    virtual void visit(FindVulnerableStatement& node) = 0;
    virtual void visit(ShowTreeStatement& node) = 0;
    virtual void visit(BlastRadiusStatement& node) = 0;

    virtual void visit(BinaryOpExpr& node) = 0;
    virtual void visit(UnaryOpExpr& node) = 0;
    virtual void visit(ColumnRefExpr& node) = 0;
    virtual void visit(LiteralExpr& node) = 0;
};

} // namespace sbom_dsl
