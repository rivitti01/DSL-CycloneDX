#pragma once

#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>

namespace sbom_dsl {

struct TreeNode {
    std::string name;
    std::string version;
    std::string ref;
    size_t depth{0};
    std::vector<TreeNode> children;
};

struct BlastRadiusMetrics {
    std::string vulnerability_id;
    std::string severity;
    double score{0.0};
    size_t total_components{0};
    size_t directly_affected_components{0};
    size_t transitively_affected_components{0};
    double impact_percentage{0.0};
    bool root_application_affected{false};
    std::vector<std::string> affected_component_names;
    std::vector<std::string> affected_paths;
};

struct GraphNodeInfo {
    std::string id;       // Unique ID in graph (e.g. ref or name)
    std::string name;     // Component display name
    std::string version;  // Component version
    std::string role;     // "root", "vulnerable", "transitive", "standard"
    std::string details;  // e.g. "CVE-2021-44228: critical"
    size_t depth{0};
};

struct GraphEdgeInfo {
    std::string from_id;
    std::string to_id;
    std::string label;
};

struct GraphData {
    std::string title{"DependencyGraph"};
    std::vector<GraphNodeInfo> nodes;
    std::vector<GraphEdgeInfo> edges;

    bool is_empty() const { return nodes.empty() && edges.empty(); }
};

struct QueryResult {
    std::vector<std::string> columns;
    std::vector<std::vector<std::string>> rows;

    std::optional<TreeNode> tree_root;
    std::optional<BlastRadiusMetrics> blast_radius;
    std::optional<GraphData> graph;

    std::string execution_backend{"NativeEngine"};
    double execution_time_ms{0.0};

    bool is_assertion{false};
    bool assertion_passed{true};
    std::string assertion_title;

    bool is_empty() const { return rows.empty() && !tree_root.has_value() && !blast_radius.has_value() && !graph.has_value() && !is_assertion; }
    size_t size() const { return rows.size(); }
};

} // namespace sbom_dsl
