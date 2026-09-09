#pragma once

#include "sbom_dsl/common/source_location.hpp"
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <variant>

namespace sbom_dsl {

class ASTVisitor;

enum class BinaryOperator {
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    And,
    Or,
    Contains,
    Matches,
    Like
};

std::string_view binary_op_to_string(BinaryOperator op);

enum class UnaryOperator {
    Not
};

std::string_view unary_op_to_string(UnaryOperator op);

enum class SeverityLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
    None
};

std::string_view severity_to_string(SeverityLevel sev);
std::optional<SeverityLevel> severity_from_string(std::string_view str);

class ASTNode {
public:
    explicit ASTNode(SourceLocation loc) : location(std::move(loc)) {}
    virtual ~ASTNode() = default;
    virtual void accept(ASTVisitor& visitor) = 0;

    SourceLocation location;
};

// Expressions
class ExpressionNode : public ASTNode {
public:
    using ASTNode::ASTNode;
};

class BinaryOpExpr : public ExpressionNode {
public:
    BinaryOpExpr(BinaryOperator op,
                 std::unique_ptr<ExpressionNode> left,
                 std::unique_ptr<ExpressionNode> right,
                 SourceLocation loc)
        : ExpressionNode(std::move(loc)), op(op), left(std::move(left)), right(std::move(right)) {}

    void accept(ASTVisitor& visitor) override;

    BinaryOperator op;
    std::unique_ptr<ExpressionNode> left;
    std::unique_ptr<ExpressionNode> right;
};

class UnaryOpExpr : public ExpressionNode {
public:
    UnaryOpExpr(UnaryOperator op, std::unique_ptr<ExpressionNode> operand, SourceLocation loc)
        : ExpressionNode(std::move(loc)), op(op), operand(std::move(operand)) {}

    void accept(ASTVisitor& visitor) override;

    UnaryOperator op;
    std::unique_ptr<ExpressionNode> operand;
};

class ColumnRefExpr : public ExpressionNode {
public:
    ColumnRefExpr(std::vector<std::string> path, SourceLocation loc)
        : ExpressionNode(std::move(loc)), path(std::move(path)) {}

    void accept(ASTVisitor& visitor) override;

    std::string full_path() const;

    std::vector<std::string> path;
};

using LiteralValue = std::variant<std::string, int64_t, double, bool, SeverityLevel>;

class LiteralExpr : public ExpressionNode {
public:
    LiteralExpr(LiteralValue value, SourceLocation loc)
        : ExpressionNode(std::move(loc)), value(std::move(value)) {}

    void accept(ASTVisitor& visitor) override;

    std::string value_as_string() const;

    LiteralValue value;
};

// Statements
class StatementNode : public ASTNode {
public:
    using ASTNode::ASTNode;
};

struct OrderByClause {
    std::string column;
    bool ascending{true};
};

bool is_aggregate_expression(std::string_view expr, std::string* func_name = nullptr, std::string* arg = nullptr);

class SelectStatement : public StatementNode {
public:
    SelectStatement(SourceLocation loc) : StatementNode(std::move(loc)) {}

    void accept(ASTVisitor& visitor) override;

    std::vector<std::string> projections; // empty means '*'
    std::string collection;               // e.g. "components"
    std::optional<std::string> bom_path;
    std::unique_ptr<ExpressionNode> where_clause;
    std::vector<std::string> group_by;
    std::optional<OrderByClause> order_by;
    std::optional<size_t> limit;

    bool has_aggregates() const;
    bool has_group_by() const { return !group_by.empty(); }
};

class WhoUsesStatement : public StatementNode {
public:
    WhoUsesStatement(std::string target, bool transitive, SourceLocation loc)
        : StatementNode(std::move(loc)), target_component(std::move(target)), is_transitive(transitive) {}

    void accept(ASTVisitor& visitor) override;

    std::string target_component;
    bool is_transitive{true};
    std::optional<std::string> bom_path;
};

class FindVulnerableStatement : public StatementNode {
public:
    FindVulnerableStatement(bool libraries_only, SourceLocation loc)
        : StatementNode(std::move(loc)), libraries_only(libraries_only) {}

    void accept(ASTVisitor& visitor) override;

    bool libraries_only{false};
    std::optional<BinaryOperator> severity_op;
    std::optional<SeverityLevel> severity_level;
    std::unique_ptr<ExpressionNode> where_clause;
    std::optional<std::string> bom_path;
};

class ShowTreeStatement : public StatementNode {
public:
    ShowTreeStatement(SourceLocation loc) : StatementNode(std::move(loc)) {}

    void accept(ASTVisitor& visitor) override;

    std::optional<std::string> root_component;
    std::optional<size_t> max_depth;
    std::optional<std::string> bom_path;
};

class BlastRadiusStatement : public StatementNode {
public:
    BlastRadiusStatement(std::string vuln_id, SourceLocation loc)
        : StatementNode(std::move(loc)), vulnerability_id(std::move(vuln_id)) {}

    void accept(ASTVisitor& visitor) override;

    std::string vulnerability_id;
    std::optional<std::string> bom_path;
};

enum class AssertTarget {
    Vulnerabilities,
    Components,
    Libraries
};

std::string_view assert_target_to_string(AssertTarget target);

class AssertStatement : public StatementNode {
public:
    AssertStatement(AssertTarget target, SourceLocation loc)
        : StatementNode(std::move(loc)), target(target) {}

    void accept(ASTVisitor& visitor) override;

    AssertTarget target{AssertTarget::Vulnerabilities};
    std::optional<BinaryOperator> severity_op;
    std::optional<SeverityLevel> severity_level;
    std::optional<double> score_threshold;
    std::unique_ptr<ExpressionNode> where_clause;
    std::optional<std::string> bom_path;
};

class ProgramNode : public ASTNode {
public:
    ProgramNode(SourceLocation loc) : ASTNode(std::move(loc)) {}

    void accept(ASTVisitor& visitor) override;

    std::vector<std::unique_ptr<StatementNode>> statements;
};

} // namespace sbom_dsl
