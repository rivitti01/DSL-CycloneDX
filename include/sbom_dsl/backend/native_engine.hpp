#pragma once

#include "sbom_dsl/ir/ir.hpp"
#include "sbom_dsl/backend/query_result.hpp"
#include "sbom_dsl/common/diagnostic.hpp"
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>

namespace sbom_dsl {

class NativeEngine {
public:
    NativeEngine() = default;

    bool load_bom_file(const std::string& path, DiagnosticEngine& diag);
    void load_bom_json(const nlohmann::json& bom);

    QueryResult execute(const IRPlan& plan, DiagnosticEngine& diag);

    // Accessors for inspections and testing
    const std::unordered_map<std::string, nlohmann::json>& components_by_ref() const { return components_by_ref_; }
    const std::unordered_map<std::string, std::vector<std::string>>& forward_graph() const { return forward_graph_; }
    const std::unordered_map<std::string, std::vector<std::string>>& reverse_graph() const { return reverse_graph_; }

private:
    void build_indices();

    std::vector<nlohmann::json> evaluate_ir_node(const IRNode& node, DiagnosticEngine& diag);
    bool evaluate_expression(const ExpressionNode& expr, const nlohmann::json& item);
    nlohmann::json resolve_field(const std::vector<std::string>& path, const nlohmann::json& item);

    std::vector<nlohmann::json> eval_scan(const IRScan& scan, DiagnosticEngine& diag);
    std::vector<nlohmann::json> eval_filter(const IRFilter& filter, DiagnosticEngine& diag);
    QueryResult eval_project(const IRProject& proj, DiagnosticEngine& diag);
    std::vector<nlohmann::json> eval_sort(const IRSort& sort, DiagnosticEngine& diag);
    std::vector<nlohmann::json> eval_limit(const IRLimit& limit, DiagnosticEngine& diag);
    std::vector<nlohmann::json> eval_hash_join(const IRHashJoin& join, DiagnosticEngine& diag);
    std::vector<nlohmann::json> eval_graph_traverse(const IRGraphTraverse& traverse, DiagnosticEngine& diag);
    QueryResult eval_blast_radius(const IRBlastRadius& blast, DiagnosticEngine& diag);

    nlohmann::json bom_data_;
    std::string loaded_file_path_;

    std::unordered_map<std::string, nlohmann::json> components_by_ref_;
    std::unordered_multimap<std::string, std::string> components_by_name_;
    std::string root_ref_;
    std::unordered_map<std::string, std::vector<std::string>> forward_graph_;
    std::unordered_map<std::string, std::vector<std::string>> reverse_graph_;
    std::vector<nlohmann::json> vulnerabilities_;
    std::unordered_multimap<std::string, nlohmann::json> affects_to_vulns_;
    GraphData current_graph_;
};

} // namespace sbom_dsl
