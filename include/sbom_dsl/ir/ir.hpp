#pragma once

#include "sbom_dsl/ast/ast.hpp"
#include <string>
#include <vector>
#include <memory>
#include <optional>

namespace sbom_dsl {

enum class IRNodeType {
    Scan,
    Filter,
    Project,
    Sort,
    Limit,
    HashJoin,
    GraphTraverse,
    BlastRadius
};

std::string_view ir_node_type_name(IRNodeType type);

enum class GraphDirection {
    Forward, // Outgoing dependencies (dependencies of A)
    Reverse  // Incoming dependencies (who uses A)
};

std::string_view graph_direction_name(GraphDirection dir);

class IRNode {
public:
    virtual ~IRNode() = default;
    virtual IRNodeType type() const = 0;
    virtual std::string description() const = 0;
};

class IRScan : public IRNode {
public:
    IRScan(std::string collection, std::optional<std::string> bom_path = std::nullopt)
        : collection(std::move(collection)), bom_path(std::move(bom_path)) {}

    IRNodeType type() const override { return IRNodeType::Scan; }
    std::string description() const override;

    std::string collection;
    std::optional<std::string> bom_path;
};

class IRFilter : public IRNode {
public:
    IRFilter(std::unique_ptr<IRNode> child, std::unique_ptr<ExpressionNode> predicate)
        : child(std::move(child)), predicate(std::move(predicate)) {}

    IRNodeType type() const override { return IRNodeType::Filter; }
    std::string description() const override;

    std::unique_ptr<IRNode> child;
    std::unique_ptr<ExpressionNode> predicate;
};

class IRProject : public IRNode {
public:
    IRProject(std::unique_ptr<IRNode> child, std::vector<std::string> projections)
        : child(std::move(child)), projections(std::move(projections)) {}

    IRNodeType type() const override { return IRNodeType::Project; }
    std::string description() const override;

    std::unique_ptr<IRNode> child;
    std::vector<std::string> projections;
};

class IRSort : public IRNode {
public:
    IRSort(std::unique_ptr<IRNode> child, std::string column, bool ascending)
        : child(std::move(child)), column(std::move(column)), ascending(ascending) {}

    IRNodeType type() const override { return IRNodeType::Sort; }
    std::string description() const override;

    std::unique_ptr<IRNode> child;
    std::string column;
    bool ascending{true};
};

class IRLimit : public IRNode {
public:
    IRLimit(std::unique_ptr<IRNode> child, size_t limit)
        : child(std::move(child)), limit(limit) {}

    IRNodeType type() const override { return IRNodeType::Limit; }
    std::string description() const override;

    std::unique_ptr<IRNode> child;
    size_t limit;
};

class IRHashJoin : public IRNode {
public:
    IRHashJoin(std::unique_ptr<IRNode> left,
               std::unique_ptr<IRNode> right,
               std::string left_key,
               std::string right_key)
        : left(std::move(left)), right(std::move(right)),
          left_key(std::move(left_key)), right_key(std::move(right_key)) {}

    IRNodeType type() const override { return IRNodeType::HashJoin; }
    std::string description() const override;

    std::unique_ptr<IRNode> left;
    std::unique_ptr<IRNode> right;
    std::string left_key;
    std::string right_key;
};

class IRGraphTraverse : public IRNode {
public:
    IRGraphTraverse(std::unique_ptr<IRNode> child,
                    std::string target_ref_or_name,
                    GraphDirection direction,
                    bool transitive,
                    std::optional<size_t> max_depth = std::nullopt)
        : child(std::move(child)), target(std::move(target_ref_or_name)),
          direction(direction), transitive(transitive), max_depth(max_depth) {}

    IRNodeType type() const override { return IRNodeType::GraphTraverse; }
    std::string description() const override;

    std::unique_ptr<IRNode> child;
    std::string target;
    GraphDirection direction{GraphDirection::Reverse};
    bool transitive{true};
    std::optional<size_t> max_depth;
};

class IRBlastRadius : public IRNode {
public:
    IRBlastRadius(std::unique_ptr<IRNode> child, std::string vulnerability_id)
        : child(std::move(child)), vulnerability_id(std::move(vulnerability_id)) {}

    IRNodeType type() const override { return IRNodeType::BlastRadius; }
    std::string description() const override;

    std::unique_ptr<IRNode> child;
    std::string vulnerability_id;
};

struct IRPlan {
    std::unique_ptr<IRNode> root;
    std::optional<std::string> bom_path;
    bool is_assertion{false};
    std::string assertion_title;
};

} // namespace sbom_dsl
