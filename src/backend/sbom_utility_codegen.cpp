#include "sbom_dsl/backend/sbom_utility_codegen.hpp"
#include <cstdio>
#include <memory>
#include <array>
#include <sstream>

namespace sbom_dsl {

bool SbomUtilityCodeGen::extract_where_filters(const ExpressionNode* expr, std::vector<std::pair<std::string, std::string>>& filters) {
    if (!expr) return true;

    if (const auto* bin = dynamic_cast<const BinaryOpExpr*>(expr)) {
        if (bin->op == BinaryOperator::And) {
            return extract_where_filters(bin->left.get(), filters) &&
                   extract_where_filters(bin->right.get(), filters);
        }
        if (bin->op == BinaryOperator::Equal) {
            const auto* col = dynamic_cast<const ColumnRefExpr*>(bin->left.get());
            const auto* lit = dynamic_cast<const LiteralExpr*>(bin->right.get());
            if (col && lit) {
                std::string val_str = lit->value_as_string();
                if (val_str.size() >= 2 && val_str.front() == '"' && val_str.back() == '"') {
                    val_str = val_str.substr(1, val_str.size() - 2);
                }
                filters.emplace_back(col->full_path(), val_str);
                return true;
            }
        }
    }
    return false; // Unsupported filter in sbom-utility (OR, NOT, <, >, etc.)
}

bool SbomUtilityCodeGen::can_offload(const IRPlan& plan, std::string* reason) {
    if (!plan.root) {
        if (reason) *reason = "Plan has no root node";
        return false;
    }

    const IRNode* curr = plan.root.get();

    // Must start with Project
    if (curr->type() != IRNodeType::Project) {
        if (reason) *reason = "Root is not an IRProject node";
        return false;
    }
    curr = static_cast<const IRProject*>(curr)->child.get();
    if (!curr) return false;

    // Optional Limit
    if (curr->type() == IRNodeType::Limit) {
        curr = static_cast<const IRLimit*>(curr)->child.get();
        if (!curr) return false;
    }

    // Optional Sort (sbom-utility query has experimental/unsupported orderby)
    if (curr->type() == IRNodeType::Sort) {
        if (reason) *reason = "sbom-utility query command does not fully support ORDER BY";
        return false;
    }

    // Optional Filter
    if (curr->type() == IRNodeType::Filter) {
        const auto* filter_node = static_cast<const IRFilter*>(curr);
        std::vector<std::pair<std::string, std::string>> filters;
        if (!extract_where_filters(filter_node->predicate.get(), filters)) {
            if (reason) *reason = "WHERE clause contains complex operators (OR, NOT, <, >, etc.) not supported by sbom-utility";
            return false;
        }
        curr = filter_node->child.get();
        if (!curr) return false;
    }

    // Must terminate with Scan
    if (curr->type() != IRNodeType::Scan) {
        if (reason) *reason = "Plan contains joins or graph traversals not supported by sbom-utility CLI";
        return false;
    }

    return true;
}

std::optional<std::string> SbomUtilityCodeGen::generate_command(const IRPlan& plan, const std::string& default_file) {
    if (!can_offload(plan)) {
        return std::nullopt;
    }

    std::string file_path = plan.bom_path.value_or(default_file);
    const auto* proj = static_cast<const IRProject*>(plan.root.get());

    const IRNode* curr = proj->child.get();
    if (curr->type() == IRNodeType::Limit) {
        curr = static_cast<const IRLimit*>(curr)->child.get();
    }

    std::vector<std::pair<std::string, std::string>> where_filters;
    if (curr->type() == IRNodeType::Filter) {
        const auto* filter_node = static_cast<const IRFilter*>(curr);
        extract_where_filters(filter_node->predicate.get(), where_filters);
        curr = filter_node->child.get();
    }

    const auto* scan_node = static_cast<const IRScan*>(curr);
    std::string collection = scan_node->collection;

    std::ostringstream cmd;
    cmd << "sbom-utility query --input-file \"" << file_path << "\" --from " << collection;

    if (!proj->projections.empty()) {
        cmd << " --select ";
        for (size_t i = 0; i < proj->projections.size(); ++i) {
            if (i > 0) cmd << ",";
            cmd << proj->projections[i];
        }
    }

    if (!where_filters.empty()) {
        cmd << " --where \"";
        for (size_t i = 0; i < where_filters.size(); ++i) {
            if (i > 0) cmd << ",";
            cmd << where_filters[i].first << "=" << where_filters[i].second;
        }
        cmd << "\"";
    }

    return cmd.str();
}

QueryResult SbomUtilityCodeGen::execute_command(const std::string& command, DiagnosticEngine& diag) {
    QueryResult result;
    result.execution_backend = "sbom-utility CLI";

    std::array<char, 256> buffer;
    std::string output;

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        diag.error(SourceLocation{}, "Failed to invoke sbom-utility command via pipe: " + command);
        return result;
    }

    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output += buffer.data();
    }

    int exit_code = pclose(pipe);
    if (exit_code != 0) {
        diag.error(SourceLocation{}, "sbom-utility exited with non-zero status (" + std::to_string(exit_code) + ")");
        return result;
    }

    try {
        auto json_data = nlohmann::json::parse(output);
        if (json_data.is_array()) {
            if (!json_data.empty() && json_data[0].is_object()) {
                for (auto& [key, _] : json_data[0].items()) {
                    result.columns.push_back(key);
                }
                for (auto& item : json_data) {
                    std::vector<std::string> row;
                    for (const auto& col : result.columns) {
                        if (item.contains(col)) {
                            row.push_back(item[col].dump());
                        } else {
                            row.push_back("");
                        }
                    }
                    result.rows.push_back(row);
                }
            }
        }
    } catch (const std::exception& e) {
        diag.error(SourceLocation{}, "Failed to parse sbom-utility JSON output: " + std::string(e.what()));
    }

    return result;
}

} // namespace sbom_dsl
