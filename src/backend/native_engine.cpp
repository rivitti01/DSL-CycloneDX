#include "sbom_dsl/backend/native_engine.hpp"
#include "sbom_dsl/ir/ir_optimizer.hpp"
#include <fstream>
#include <queue>
#include <regex>
#include <chrono>
#include <algorithm>
#include <cctype>

namespace sbom_dsl {

namespace {

std::string sql_like_to_regex(std::string_view pattern) {
    std::string rx = "^";
    for (size_t i = 0; i < pattern.size(); ++i) {
        char c = pattern[i];
        if (c == '%') {
            rx += ".*";
        } else if (c == '_') {
            rx += ".";
        } else if (c == '\\' && i + 1 < pattern.size()) {
            char next = pattern[++i];
            if (std::string_view("^$.*+?()[]{}|\\").find(next) != std::string_view::npos) {
                rx += '\\';
            }
            rx += next;
        } else {
            if (std::string_view("^$.*+?()[]{}|\\").find(c) != std::string_view::npos) {
                rx += '\\';
            }
            rx += c;
        }
    }
    rx += "$";
    return rx;
}

bool case_insensitive_contains(std::string_view str, std::string_view sub) {
    if (sub.empty()) return true;
    auto it = std::search(
        str.begin(), str.end(),
        sub.begin(), sub.end(),
        [](char ch1, char ch2) {
            return std::tolower(static_cast<unsigned char>(ch1)) ==
                   std::tolower(static_cast<unsigned char>(ch2));
        }
    );
    return it != str.end();
}

} // anonymous namespace

bool NativeEngine::load_bom_file(const std::string& path, DiagnosticEngine& diag) {
    std::ifstream file(path);
    if (!file.is_open()) {
        diag.error(SourceLocation{}, "Cannot open CycloneDX SBOM file: " + path);
        return false;
    }
    try {
        nlohmann::json data;
        file >> data;
        load_bom_json(data);
        loaded_file_path_ = path;
        return true;
    } catch (const std::exception& e) {
        diag.error(SourceLocation{}, "JSON parse error in file " + path + ": " + e.what());
        return false;
    }
}

void NativeEngine::load_bom_json(const nlohmann::json& bom) {
    bom_data_ = bom;
    build_indices();
}

void NativeEngine::build_indices() {
    components_by_ref_.clear();
    components_by_name_.clear();
    forward_graph_.clear();
    reverse_graph_.clear();
    vulnerabilities_.clear();
    affects_to_vulns_.clear();
    root_ref_.clear();

    // 1. Metadata root component
    if (bom_data_.contains("metadata") && bom_data_["metadata"].contains("component")) {
        auto& root_comp = bom_data_["metadata"]["component"];
        std::string ref = root_comp.value("bom-ref", "root-app");
        root_ref_ = ref;
        components_by_ref_[ref] = root_comp;
        if (root_comp.contains("name")) {
            components_by_name_.emplace(root_comp["name"].get<std::string>(), ref);
        }
    }

    // 2. Components list
    if (bom_data_.contains("components") && bom_data_["components"].is_array()) {
        for (const auto& comp : bom_data_["components"]) {
            std::string ref = comp.value("bom-ref", "");
            if (ref.empty()) {
                ref = comp.value("purl", comp.value("name", ""));
            }
            if (!ref.empty()) {
                components_by_ref_[ref] = comp;
                if (comp.contains("name")) {
                    components_by_name_.emplace(comp["name"].get<std::string>(), ref);
                }
            }
        }
    }

    // 3. Dependencies graph
    if (bom_data_.contains("dependencies") && bom_data_["dependencies"].is_array()) {
        for (const auto& dep : bom_data_["dependencies"]) {
            std::string parent_ref = dep.value("ref", "");
            if (parent_ref.empty()) continue;

            if (dep.contains("dependsOn") && dep["dependsOn"].is_array()) {
                for (const auto& child_elem : dep["dependsOn"]) {
                    std::string child_ref = child_elem.get<std::string>();
                    forward_graph_[parent_ref].push_back(child_ref);
                    reverse_graph_[child_ref].push_back(parent_ref);
                }
            }
        }
    }

    // 4. Vulnerabilities
    if (bom_data_.contains("vulnerabilities") && bom_data_["vulnerabilities"].is_array()) {
        for (const auto& vuln : bom_data_["vulnerabilities"]) {
            vulnerabilities_.push_back(vuln);
            if (vuln.contains("affects") && vuln["affects"].is_array()) {
                for (const auto& aff : vuln["affects"]) {
                    std::string aff_ref = aff.value("ref", "");
                    if (!aff_ref.empty()) {
                        affects_to_vulns_.emplace(aff_ref, vuln);
                    }
                }
            }
        }
    }
}

nlohmann::json NativeEngine::resolve_field(const std::vector<std::string>& path, const nlohmann::json& item) {
    if (path.empty()) return nullptr;

    std::string full_key;
    for (size_t i = 0; i < path.size(); ++i) {
        if (i > 0) full_key += ".";
        full_key += path[i];
    }

    if (full_key == "severity" || full_key == "cvss-severity" || full_key == "ratings.severity") {
        if (item.contains("ratings") && item["ratings"].is_array() && !item["ratings"].empty()) {
            return item["ratings"][0].value("severity", "");
        }
        return item.value("severity", "");
    }
    if (full_key == "score" || full_key == "ratings.score") {
        if (item.contains("ratings") && item["ratings"].is_array() && !item["ratings"].empty()) {
            return item["ratings"][0].value("score", 0.0);
        }
        return item.value("score", 0.0);
    }
    if (full_key == "cwe" || full_key == "cwes") {
        if (item.contains("cwes") && item["cwes"].is_array() && !item["cwes"].empty()) {
            return item["cwes"][0];
        }
        return item.value("cwe", 0);
    }
    if (full_key == "vuln_id" || full_key == "id") {
        return item.value("id", "");
    }

    nlohmann::json curr = item;
    for (const auto& part : path) {
        if (curr.is_array() && !curr.empty()) {
            curr = curr[0];
        }
        if (!curr.is_object() || !curr.contains(part)) {
            return nullptr;
        }
        curr = curr[part];
    }
    return curr;
}

bool NativeEngine::evaluate_expression(const ExpressionNode& expr, const nlohmann::json& item) {
    if (const auto* lit = dynamic_cast<const LiteralExpr*>(&expr)) {
        if (std::holds_alternative<bool>(lit->value)) {
            return std::get<bool>(lit->value);
        }
    }

    if (const auto* bin = dynamic_cast<const BinaryOpExpr*>(&expr)) {
        if (bin->op == BinaryOperator::And) {
            return evaluate_expression(*bin->left, item) && evaluate_expression(*bin->right, item);
        }
        if (bin->op == BinaryOperator::Or) {
            return evaluate_expression(*bin->left, item) || evaluate_expression(*bin->right, item);
        }

        const auto* lit_l = dynamic_cast<const LiteralExpr*>(bin->left.get());
        const auto* lit_r = dynamic_cast<const LiteralExpr*>(bin->right.get());
        if (lit_l && lit_r) {
            IROptimizer opt;
            auto folded = opt.fold_expression(clone_expression(&expr));
            if (const auto* f_lit = dynamic_cast<const LiteralExpr*>(folded.get())) {
                if (std::holds_alternative<bool>(f_lit->value)) {
                    return std::get<bool>(f_lit->value);
                }
            }
        }

        const auto* col = dynamic_cast<const ColumnRefExpr*>(bin->left.get());
        const auto* lit = dynamic_cast<const LiteralExpr*>(bin->right.get());
        bool reversed = false;
        if (!col || !lit) {
            col = dynamic_cast<const ColumnRefExpr*>(bin->right.get());
            lit = dynamic_cast<const LiteralExpr*>(bin->left.get());
            reversed = true;
        }
        if (!col || !lit) return true;

        nlohmann::json field_val = resolve_field(col->path, item);
        if (field_val.is_null()) return false;

        return std::visit([&](const auto& target_val) -> bool {
            using T = std::decay_t<decltype(target_val)>;

            if constexpr (std::is_same_v<T, std::string>) {
                std::string s_val = field_val.is_string() ? field_val.get<std::string>() : field_val.dump();
                const std::string& pat = reversed ? s_val : target_val;
                const std::string& text = reversed ? target_val : s_val;

                if (bin->op == BinaryOperator::Equal) return s_val == target_val;
                if (bin->op == BinaryOperator::NotEqual) return s_val != target_val;
                if (bin->op == BinaryOperator::Contains) {
                    return case_insensitive_contains(text, pat);
                }
                if (bin->op == BinaryOperator::Like) {
                    try {
                        std::regex re(sql_like_to_regex(pat), std::regex_constants::icase);
                        return std::regex_match(text, re);
                    } catch (...) {
                        return false;
                    }
                }
                if (bin->op == BinaryOperator::Matches) {
                    try {
                        std::regex re(pat, std::regex_constants::icase);
                        return std::regex_search(text, re);
                    } catch (...) {
                        return false;
                    }
                }
                if (bin->op == BinaryOperator::Less) return reversed ? target_val < s_val : s_val < target_val;
                if (bin->op == BinaryOperator::LessEqual) return reversed ? target_val <= s_val : s_val <= target_val;
                if (bin->op == BinaryOperator::Greater) return reversed ? target_val > s_val : s_val > target_val;
                if (bin->op == BinaryOperator::GreaterEqual) return reversed ? target_val >= s_val : s_val >= target_val;
                return false;
            } else if constexpr (std::is_same_v<T, int64_t> || std::is_same_v<T, double>) {
                double d_field = field_val.is_number() ? field_val.get<double>() : 0.0;
                double d_target = static_cast<double>(target_val);
                double left_v = reversed ? d_target : d_field;
                double right_v = reversed ? d_field : d_target;
                if (bin->op == BinaryOperator::Equal) return left_v == right_v;
                if (bin->op == BinaryOperator::NotEqual) return left_v != right_v;
                if (bin->op == BinaryOperator::Less) return left_v < right_v;
                if (bin->op == BinaryOperator::LessEqual) return left_v <= right_v;
                if (bin->op == BinaryOperator::Greater) return left_v > right_v;
                if (bin->op == BinaryOperator::GreaterEqual) return left_v >= right_v;
                return false;
            } else if constexpr (std::is_same_v<T, bool>) {
                bool b_field = field_val.is_boolean() ? field_val.get<bool>() : false;
                if (bin->op == BinaryOperator::Equal) return b_field == target_val;
                if (bin->op == BinaryOperator::NotEqual) return b_field != target_val;
                return false;
            } else if constexpr (std::is_same_v<T, SeverityLevel>) {
                std::string s_val = field_val.is_string() ? field_val.get<std::string>() : "";
                auto item_sev = severity_from_string(s_val);
                if (!item_sev.has_value()) return false;

                // Rank: None=0, Info=1, Low=2, Medium=3, High=4, Critical=5
                auto rank = [](SeverityLevel s) -> int {
                    switch (s) {
                        case SeverityLevel::None: return 0;
                        case SeverityLevel::Info: return 1;
                        case SeverityLevel::Low: return 2;
                        case SeverityLevel::Medium: return 3;
                        case SeverityLevel::High: return 4;
                        case SeverityLevel::Critical: return 5;
                    }
                    return 0;
                };

                int r_item = rank(*item_sev);
                int r_target = rank(target_val);
                int left_r = reversed ? r_target : r_item;
                int right_r = reversed ? r_item : r_target;
                if (bin->op == BinaryOperator::Equal) return left_r == right_r;
                if (bin->op == BinaryOperator::NotEqual) return left_r != right_r;
                if (bin->op == BinaryOperator::Less) return left_r < right_r;
                if (bin->op == BinaryOperator::LessEqual) return left_r <= right_r;
                if (bin->op == BinaryOperator::Greater) return left_r > right_r;
                if (bin->op == BinaryOperator::GreaterEqual) return left_r >= right_r;
                return false;
            }
            return false;
        }, lit->value);
    }

    if (const auto* un = dynamic_cast<const UnaryOpExpr*>(&expr)) {
        if (un->op == UnaryOperator::Not) {
            return !evaluate_expression(*un->operand, item);
        }
    }

    return true;
}

std::vector<nlohmann::json> NativeEngine::eval_scan(const IRScan& scan, DiagnosticEngine& diag) {
    if (scan.bom_path && (!bom_data_.is_object() || loaded_file_path_ != *scan.bom_path)) {
        load_bom_file(*scan.bom_path, diag);
    }

    std::vector<nlohmann::json> results;

    if (scan.collection == "components") {
        for (const auto& [_, comp] : components_by_ref_) {
            results.push_back(comp);
        }
    } else if (scan.collection == "vulnerabilities") {
        results = vulnerabilities_;
    } else if (scan.collection == "dependencies") {
        if (bom_data_.contains("dependencies") && bom_data_["dependencies"].is_array()) {
            for (const auto& d : bom_data_["dependencies"]) {
                results.push_back(d);
            }
        }
    } else if (scan.collection == "metadata.component") {
        if (bom_data_.contains("metadata") && bom_data_["metadata"].contains("component")) {
            results.push_back(bom_data_["metadata"]["component"]);
        }
    }
    return results;
}

std::vector<nlohmann::json> NativeEngine::eval_filter(const IRFilter& filter, DiagnosticEngine& diag) {
    if (filter.predicate && IROptimizer::is_false_literal(filter.predicate.get())) {
        return {};
    }

    auto items = evaluate_ir_node(*filter.child, diag);
    if (!filter.predicate) return items;

    std::vector<nlohmann::json> filtered;
    for (const auto& item : items) {
        if (evaluate_expression(*filter.predicate, item)) {
            filtered.push_back(item);
        }
    }
    return filtered;
}

std::vector<nlohmann::json> NativeEngine::eval_sort(const IRSort& sort, DiagnosticEngine& diag) {
    auto items = evaluate_ir_node(*sort.child, diag);
    std::sort(items.begin(), items.end(), [&](const nlohmann::json& a, const nlohmann::json& b) {
        nlohmann::json va = a.value(sort.column, "");
        nlohmann::json vb = b.value(sort.column, "");
        if (sort.ascending) {
            return va < vb;
        } else {
            return va > vb;
        }
    });
    return items;
}

std::vector<nlohmann::json> NativeEngine::eval_limit(const IRLimit& limit, DiagnosticEngine& diag) {
    auto items = evaluate_ir_node(*limit.child, diag);
    if (items.size() > limit.limit) {
        items.resize(limit.limit);
    }
    return items;
}

std::vector<nlohmann::json> NativeEngine::eval_hash_join(const IRHashJoin& join, DiagnosticEngine& diag) {
    auto left_items = evaluate_ir_node(*join.left, diag);
    auto right_items = evaluate_ir_node(*join.right, diag);

    // Build index on right items using right_key
    std::unordered_multimap<std::string, nlohmann::json> right_index;
    for (const auto& r : right_items) {
        std::string key;
        if (r.contains(join.right_key)) {
            key = r[join.right_key].is_string() ? r[join.right_key].get<std::string>() : r[join.right_key].dump();
        } else if (join.right_key == "bom-ref") {
            key = r.value("bom-ref", r.value("purl", ""));
        }
        if (!key.empty()) {
            right_index.emplace(key, r);
        }
    }

    std::vector<nlohmann::json> joined_results;

    for (const auto& l : left_items) {
        std::vector<std::string> keys_to_lookup;

        if (join.left_key == "affects") {
            if (l.contains("affects") && l["affects"].is_array()) {
                for (const auto& aff : l["affects"]) {
                    std::string ref = aff.value("ref", "");
                    if (!ref.empty()) keys_to_lookup.push_back(ref);
                }
            }
        } else if (l.contains(join.left_key)) {
            std::string k = l[join.left_key].is_string() ? l[join.left_key].get<std::string>() : l[join.left_key].dump();
            if (!k.empty()) keys_to_lookup.push_back(k);
        }

        for (const auto& k : keys_to_lookup) {
            auto range = right_index.equal_range(k);
            for (auto it = range.first; it != range.second; ++it) {
                nlohmann::json merged = it->second; // Component fields
                for (auto& [lk, lv] : l.items()) {
                    if (lk == "id") merged["vuln_id"] = lv;
                    else if (!merged.contains(lk)) merged[lk] = lv;
                }
                joined_results.push_back(merged);
            }
        }
    }

    return joined_results;
}

std::vector<nlohmann::json> NativeEngine::eval_graph_traverse(const IRGraphTraverse& traverse, DiagnosticEngine& diag) {
    if (traverse.child) {
        evaluate_ir_node(*traverse.child, diag);
    }

    std::vector<nlohmann::json> reached_nodes;
    std::unordered_set<std::string> visited;

    // Resolve target to bom-ref(s)
    std::vector<std::string> start_refs;
    if (components_by_ref_.find(traverse.target) != components_by_ref_.end()) {
        start_refs.push_back(traverse.target);
    } else {
        auto range = components_by_name_.equal_range(traverse.target);
        for (auto it = range.first; it != range.second; ++it) {
            start_refs.push_back(it->second);
        }
    }

    if (start_refs.empty() && !traverse.target.empty()) {
        // Try substring search on name or purl
        for (const auto& [ref, comp] : components_by_ref_) {
            std::string name = comp.value("name", "");
            if (name.find(traverse.target) != std::string::npos || ref.find(traverse.target) != std::string::npos) {
                start_refs.push_back(ref);
            }
        }
    }

    // If start_refs is empty and direction is Forward, default to root_ref_
    if (start_refs.empty() && traverse.direction == GraphDirection::Forward) {
        if (!root_ref_.empty()) start_refs.push_back(root_ref_);
    }

    const auto& graph = (traverse.direction == GraphDirection::Reverse) ? reverse_graph_ : forward_graph_;

    current_graph_ = GraphData{};
    current_graph_.title = (traverse.direction == GraphDirection::Forward) ? "DependencyTree" : "WhoUses";

    auto get_comp_name = [&](const std::string& ref) -> std::string {
        auto cit = components_by_ref_.find(ref);
        if (cit != components_by_ref_.end()) return cit->second.value("name", ref);
        return ref;
    };
    auto get_comp_ver = [&](const std::string& ref) -> std::string {
        auto cit = components_by_ref_.find(ref);
        if (cit != components_by_ref_.end()) return cit->second.value("version", "");
        return "";
    };
    auto get_comp_vuln = [&](const std::string& ref) -> std::pair<std::string, std::string> {
        auto vrange = affects_to_vulns_.equal_range(ref);
        if (vrange.first != vrange.second) {
            const auto& v = vrange.first->second;
            std::string vid = v.value("id", "");
            std::string vsev = "";
            if (v.contains("ratings") && v["ratings"].is_array() && !v["ratings"].empty()) {
                vsev = v["ratings"][0].value("severity", "");
            }
            std::string details = vid + (!vsev.empty() ? (": " + vsev) : "");
            return {"vulnerable", details};
        }
        return {"standard", ""};
    };

    std::queue<std::pair<std::string, size_t>> queue;
    for (const auto& r : start_refs) {
        queue.push({r, 0});
        visited.insert(r);

        std::string r_name = get_comp_name(r);
        std::string r_ver = get_comp_ver(r);
        auto [vuln_role, vuln_details] = get_comp_vuln(r);
        std::string role = (traverse.direction == GraphDirection::Forward || r == root_ref_) ? "root" : vuln_role;
        current_graph_.nodes.push_back({r_name, r_name, r_ver, role, vuln_details, 0});
    }

    while (!queue.empty()) {
        auto [curr_ref, depth] = queue.front();
        queue.pop();

        if (depth > 0) { // Exclude starting target itself from results
            nlohmann::json node_entry;
            node_entry["ref"] = curr_ref;
            node_entry["depth"] = depth;
            reached_nodes.push_back(node_entry);
        }

        if (traverse.max_depth && depth >= *traverse.max_depth) {
            continue;
        }

        if (!traverse.transitive && depth >= 1) {
            continue;
        }

        auto it = graph.find(curr_ref);
        if (it != graph.end()) {
            for (const auto& neighbor : it->second) {
                std::string curr_name = get_comp_name(curr_ref);
                std::string neighbor_name = get_comp_name(neighbor);

                if (visited.find(neighbor) == visited.end()) {
                    visited.insert(neighbor);
                    queue.push({neighbor, depth + 1});

                    std::string n_ver = get_comp_ver(neighbor);
                    auto [vuln_role, vuln_details] = get_comp_vuln(neighbor);
                    current_graph_.nodes.push_back({neighbor_name, neighbor_name, n_ver, vuln_role, vuln_details, depth + 1});
                }

                if (traverse.direction == GraphDirection::Forward) {
                    current_graph_.edges.push_back({curr_name, neighbor_name, ""});
                } else {
                    current_graph_.edges.push_back({neighbor_name, curr_name, ""});
                }
            }
        }
    }

    return reached_nodes;
}

QueryResult NativeEngine::eval_blast_radius(const IRBlastRadius& blast, DiagnosticEngine& diag) {
    if (blast.child) {
        evaluate_ir_node(*blast.child, diag);
    }

    QueryResult res;
    res.execution_backend = "Native CycloneDX Engine";

    BlastRadiusMetrics metrics;
    metrics.vulnerability_id = blast.vulnerability_id;
    metrics.total_components = components_by_ref_.size();

    // Find vulnerability details
    nlohmann::json vuln_obj = nullptr;
    for (const auto& v : vulnerabilities_) {
        if (v.value("id", "") == blast.vulnerability_id) {
            vuln_obj = v;
            break;
        }
    }

    if (vuln_obj.is_null()) {
        diag.warning(SourceLocation{}, "Vulnerability '" + blast.vulnerability_id + "' not found in SBOM vulnerabilities catalog");
        res.blast_radius = metrics;
        return res;
    }

    if (vuln_obj.contains("ratings") && vuln_obj["ratings"].is_array() && !vuln_obj["ratings"].empty()) {
        metrics.severity = vuln_obj["ratings"][0].value("severity", "UNKNOWN");
        metrics.score = vuln_obj["ratings"][0].value("score", 0.0);
    }

    // Find affected components
    std::unordered_set<std::string> directly_affected;
    if (vuln_obj.contains("affects") && vuln_obj["affects"].is_array()) {
        for (const auto& aff : vuln_obj["affects"]) {
            std::string ref = aff.value("ref", "");
            if (!ref.empty()) {
                directly_affected.insert(ref);
            }
        }
    }
    metrics.directly_affected_components = directly_affected.size();

    // Reverse BFS reachability to find all transitively impacted components
    std::unordered_set<std::string> all_impacted = directly_affected;
    std::queue<std::string> queue;
    for (const auto& ref : directly_affected) {
        queue.push(ref);
    }

    while (!queue.empty()) {
        std::string curr = queue.front();
        queue.pop();

        auto it = reverse_graph_.find(curr);
        if (it != reverse_graph_.end()) {
            for (const auto& parent : it->second) {
                if (all_impacted.find(parent) == all_impacted.end()) {
                    all_impacted.insert(parent);
                    queue.push(parent);
                }
            }
        }
    }

    metrics.transitively_affected_components = all_impacted.size();
    if (metrics.total_components > 0) {
        metrics.impact_percentage = (static_cast<double>(all_impacted.size()) / static_cast<double>(metrics.total_components)) * 100.0;
    }

    if (!root_ref_.empty() && all_impacted.find(root_ref_) != all_impacted.end()) {
        metrics.root_application_affected = true;
    }

    for (const auto& ref : all_impacted) {
        auto cit = components_by_ref_.find(ref);
        if (cit != components_by_ref_.end()) {
            metrics.affected_component_names.push_back(cit->second.value("name", ref));
        } else {
            metrics.affected_component_names.push_back(ref);
        }
    }

    res.columns = {"Metric", "Value"};
    res.rows = {
        {"Vulnerability ID", metrics.vulnerability_id},
        {"CVSS Severity", metrics.severity},
        {"CVSS Score", std::to_string(metrics.score)},
        {"Total Components in SBOM", std::to_string(metrics.total_components)},
        {"Directly Affected Components", std::to_string(metrics.directly_affected_components)},
        {"Transitively Impacted Components", std::to_string(metrics.transitively_affected_components)},
        {"Blast Radius (%)", std::to_string(metrics.impact_percentage) + "%"},
        {"Root Application Exposed?", metrics.root_application_affected ? "YES (CRITICAL IMPACT)" : "NO"}
    };

    res.blast_radius = metrics;

    // Construct visual graph for Blast Radius
    GraphData blast_graph;
    blast_graph.title = "BlastRadius_" + metrics.vulnerability_id;

    auto get_comp_name = [&](const std::string& ref) -> std::string {
        auto cit = components_by_ref_.find(ref);
        if (cit != components_by_ref_.end()) return cit->second.value("name", ref);
        return ref;
    };
    auto get_comp_ver = [&](const std::string& ref) -> std::string {
        auto cit = components_by_ref_.find(ref);
        if (cit != components_by_ref_.end()) return cit->second.value("version", "");
        return "";
    };

    for (const auto& ref : all_impacted) {
        std::string name = get_comp_name(ref);
        std::string ver = get_comp_ver(ref);
        std::string role = "transitive";
        std::string details = "";

        if (directly_affected.count(ref)) {
            role = "vulnerable";
            details = metrics.vulnerability_id + " [" + metrics.severity + "]";
        } else if (ref == root_ref_) {
            role = "root";
            details = "Root Application";
        }

        blast_graph.nodes.push_back({name, name, ver, role, details, 0});
    }

    for (const auto& child_ref : all_impacted) {
        auto it = reverse_graph_.find(child_ref);
        if (it != reverse_graph_.end()) {
            for (const auto& parent_ref : it->second) {
                if (all_impacted.count(parent_ref)) {
                    std::string p_name = get_comp_name(parent_ref);
                    std::string c_name = get_comp_name(child_ref);
                    blast_graph.edges.push_back({p_name, c_name, ""});
                }
            }
        }
    }

    res.graph = blast_graph;
    return res;
}

std::vector<nlohmann::json> NativeEngine::evaluate_ir_node(const IRNode& node, DiagnosticEngine& diag) {
    switch (node.type()) {
        case IRNodeType::Scan:
            return eval_scan(static_cast<const IRScan&>(node), diag);
        case IRNodeType::Filter:
            return eval_filter(static_cast<const IRFilter&>(node), diag);
        case IRNodeType::Sort:
            return eval_sort(static_cast<const IRSort&>(node), diag);
        case IRNodeType::Limit:
            return eval_limit(static_cast<const IRLimit&>(node), diag);
        case IRNodeType::HashJoin:
            return eval_hash_join(static_cast<const IRHashJoin&>(node), diag);
        case IRNodeType::GraphTraverse:
            return eval_graph_traverse(static_cast<const IRGraphTraverse&>(node), diag);
        case IRNodeType::Project:
        case IRNodeType::BlastRadius:
            // Handled in execute()
            return {};
    }
    return {};
}

QueryResult NativeEngine::eval_project(const IRProject& proj, DiagnosticEngine& diag) {
    auto items = evaluate_ir_node(*proj.child, diag);
    QueryResult res;
    res.execution_backend = "Native CycloneDX Engine";

    if (items.empty()) return res;

    // Determine columns
    if (proj.projections.empty()) {
        // Project all top-level keys of first element
        for (auto& [key, _] : items[0].items()) {
            res.columns.push_back(key);
        }
    } else {
        res.columns = proj.projections;
    }

    for (const auto& item : items) {
        std::vector<std::string> row;
        row.reserve(res.columns.size());
        for (const auto& col : res.columns) {
            nlohmann::json val = resolve_field({col}, item);
            if (val.is_null()) {
                row.push_back("-");
            } else if (val.is_string()) {
                row.push_back(val.get<std::string>());
            } else {
                row.push_back(val.dump());
            }
        }
        res.rows.push_back(std::move(row));
    }

    return res;
}

QueryResult NativeEngine::execute(const IRPlan& plan, DiagnosticEngine& diag) {
    auto start_time = std::chrono::high_resolution_clock::now();

    if (plan.bom_path) {
        load_bom_file(*plan.bom_path, diag);
    }

    QueryResult res;
    current_graph_ = GraphData{};
    if (!plan.root) return res;

    if (plan.root->type() == IRNodeType::BlastRadius) {
        res = eval_blast_radius(static_cast<const IRBlastRadius&>(*plan.root), diag);
    } else if (plan.root->type() == IRNodeType::Project) {
        res = eval_project(static_cast<const IRProject&>(*plan.root), diag);
    } else {
        auto items = evaluate_ir_node(*plan.root, diag);
        res.columns = {"Result"};
        for (const auto& item : items) {
            res.rows.push_back({item.dump()});
        }
    }

    if (!res.graph.has_value() && !current_graph_.nodes.empty()) {
        res.graph = std::move(current_graph_);
    }

    if (plan.is_assertion) {
        res.is_assertion = true;
        res.assertion_title = plan.assertion_title;
        res.assertion_passed = res.rows.empty();
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    res.execution_time_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    return res;
}

} // namespace sbom_dsl
