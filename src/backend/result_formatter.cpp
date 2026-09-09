#include "sbom_dsl/backend/result_formatter.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <nlohmann/json.hpp>

namespace sbom_dsl {

std::string ResultFormatter::format(const QueryResult& result, OutputFormat fmt) {
    switch (fmt) {
        case OutputFormat::Table: return to_table(result);
        case OutputFormat::Json: return to_json(result);
        case OutputFormat::Tree: return to_tree(result);
        case OutputFormat::Dot: return to_dot(result);
        case OutputFormat::Mermaid: return to_mermaid(result);
    }
    return to_table(result);
}

std::string ResultFormatter::to_table(const QueryResult& result) {
    std::ostringstream oss;

    if (result.is_assertion) {
        if (result.assertion_passed) {
            oss << "[POLICY ASSERTION PASSED] " << result.assertion_title << "\n";
            oss << "Status: COMPLIANT (0 offending records detected in SBOM)\n";
            oss << "Total: 0 violations [Backend: " << result.execution_backend
                << ", Time: " << std::fixed << std::setprecision(2) << result.execution_time_ms << " ms]\n";
            return oss.str();
        } else {
            oss << "[POLICY ASSERTION FAILED] " << result.assertion_title << "\n";
            oss << "Status: NON-COMPLIANT (" << result.rows.size() << " offending record(s) found)\n\n";
        }
    }

    if (result.columns.empty()) {
        return oss.str() + "(empty result set, 0 rows)\n";
    }

    // Calculate maximum width for each column
    std::vector<size_t> col_widths(result.columns.size(), 0);
    for (size_t i = 0; i < result.columns.size(); ++i) {
        col_widths[i] = std::max(col_widths[i], result.columns[i].size());
    }
    for (const auto& row : result.rows) {
        for (size_t i = 0; i < row.size() && i < col_widths.size(); ++i) {
            col_widths[i] = std::max(col_widths[i], row[i].size());
        }
    }

    // Helper to draw horizontal line
    auto draw_separator = [&](char junction, char line) {
        oss << junction;
        for (size_t i = 0; i < col_widths.size(); ++i) {
            oss << std::string(col_widths[i] + 2, line) << junction;
        }
        oss << "\n";
    };

    draw_separator('+', '-');

    // Header row
    oss << "|";
    for (size_t i = 0; i < result.columns.size(); ++i) {
        oss << " " << std::left << std::setw(static_cast<int>(col_widths[i])) << result.columns[i] << " |";
    }
    oss << "\n";

    draw_separator('+', '=');

    // Data rows
    if (result.rows.empty()) {
        oss << "| (no records match query criteria)" << "\n";
    } else {
        for (const auto& row : result.rows) {
            oss << "|";
            for (size_t i = 0; i < col_widths.size(); ++i) {
                std::string cell = (i < row.size()) ? row[i] : "";
                oss << " " << std::left << std::setw(static_cast<int>(col_widths[i])) << cell << " |";
            }
            oss << "\n";
        }
    }

    draw_separator('+', '-');
    oss << "Total: " << result.rows.size() << " row(s) [Backend: " 
        << result.execution_backend << ", Time: " 
        << std::fixed << std::setprecision(2) << result.execution_time_ms << " ms]\n";

    return oss.str();
}

std::string ResultFormatter::to_json(const QueryResult& result) {
    if (result.is_assertion) {
        nlohmann::json res_obj;
        res_obj["assertion"] = true;
        res_obj["title"] = result.assertion_title;
        res_obj["passed"] = result.assertion_passed;
        res_obj["violations_count"] = result.rows.size();
        nlohmann::json violations = nlohmann::json::array();
        for (const auto& row : result.rows) {
            nlohmann::json obj;
            for (size_t i = 0; i < result.columns.size() && i < row.size(); ++i) {
                obj[result.columns[i]] = row[i];
            }
            violations.push_back(obj);
        }
        res_obj["violations"] = violations;
        return res_obj.dump(2) + "\n";
    }

    nlohmann::json j_array = nlohmann::json::array();
    for (const auto& row : result.rows) {
        nlohmann::json obj;
        for (size_t i = 0; i < result.columns.size() && i < row.size(); ++i) {
            obj[result.columns[i]] = row[i];
        }
        j_array.push_back(obj);
    }
    return j_array.dump(2) + "\n";
}

std::string ResultFormatter::to_tree(const QueryResult& result) {
    if (result.rows.empty()) {
        return "(empty dependency tree)\n";
    }

    std::ostringstream oss;
    oss << "Dependency Tree:\n";

    size_t depth_col_idx = 0;
    bool has_depth = false;
    for (size_t i = 0; i < result.columns.size(); ++i) {
        if (result.columns[i] == "depth") {
            depth_col_idx = i;
            has_depth = true;
            break;
        }
    }

    for (const auto& row : result.rows) {
        size_t depth = 1;
        if (has_depth && depth_col_idx < row.size()) {
            try {
                depth = std::stoul(row[depth_col_idx]);
            } catch (...) {
                depth = 1;
            }
        }
        for (size_t d = 1; d < depth; ++d) {
            oss << "│   ";
        }
        oss << "└── ";
        std::string name = (!row.empty()) ? row[0] : "unknown";
        std::string ver = (row.size() > 1) ? ("@" + row[1]) : "";
        oss << name << ver << "\n";
    }
    return oss.str();
}

namespace {

std::string sanitize_mermaid_id(const std::string& raw) {
    if (raw.empty()) return "node_empty";
    std::string s;
    for (char c : raw) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
            s += c;
        } else {
            s += '_';
        }
    }
    if (std::isdigit(static_cast<unsigned char>(s[0]))) {
        s = "n_" + s;
    }
    return s;
}

std::string escape_dot_string(const std::string& str) {
    std::string out;
    for (char c : str) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else out += c;
    }
    return out;
}

std::string escape_mermaid_label(const std::string& str) {
    std::string out;
    for (char c : str) {
        if (c == '"') out += "#quot;";
        else if (c == '\n') out += "<br/>";
        else out += c;
    }
    return out;
}

GraphData extract_fallback_graph(const QueryResult& result) {
    GraphData gd;
    gd.title = "QueryResult";

    if (result.blast_radius.has_value()) {
        const auto& br = *result.blast_radius;
        gd.title = "BlastRadius";

        if (br.root_application_affected) {
            gd.nodes.push_back({
                "root_app",
                "Root Application",
                "",
                "root",
                "Root Component Affected",
                0
            });
        }

        for (size_t i = 0; i < br.affected_component_names.size(); ++i) {
            const auto& cname = br.affected_component_names[i];
            bool is_direct = (i == 0 || cname == br.vulnerability_id);
            std::string role = is_direct ? "vulnerable" : "transitive";
            std::string details = is_direct ? (br.vulnerability_id + " [" + br.severity + "]") : "";
            gd.nodes.push_back({
                cname,
                cname,
                "",
                role,
                details,
                1
            });
        }

        if (gd.nodes.size() > 1) {
            for (size_t i = 0; i + 1 < gd.nodes.size(); ++i) {
                gd.edges.push_back({gd.nodes[i].id, gd.nodes[i+1].id, ""});
            }
        }
        return gd;
    }

    // Check if result has rows with depth column
    size_t depth_col = 0;
    bool has_depth = false;
    for (size_t i = 0; i < result.columns.size(); ++i) {
        if (result.columns[i] == "depth") {
            depth_col = i;
            has_depth = true;
            break;
        }
    }

    if (has_depth) {
        gd.title = "DependencyTree";
        std::vector<std::pair<size_t, std::string>> stack;

        for (size_t r = 0; r < result.rows.size(); ++r) {
            const auto& row = result.rows[r];
            std::string name = row.empty() ? ("node_" + std::to_string(r)) : row[0];
            std::string ver = (row.size() > 1) ? row[1] : "";
            size_t depth = 1;
            try {
                depth = std::stoul(row[depth_col]);
            } catch (...) {
                depth = 1;
            }

            gd.nodes.push_back({
                name,
                name,
                ver,
                (depth == 0 ? "root" : "standard"),
                "",
                depth
            });

            while (!stack.empty() && stack.back().first >= depth) {
                stack.pop_back();
            }

            if (!stack.empty()) {
                gd.edges.push_back({stack.back().second, name, ""});
            }
            stack.push_back({depth, name});
        }
        return gd;
    }

    if (!result.rows.empty()) {
        gd.title = "TabularResult";
        for (size_t i = 0; i < result.rows.size(); ++i) {
            std::string name = result.rows[i].empty() ? ("item_" + std::to_string(i)) : result.rows[i][0];
            std::string ver = (result.rows[i].size() > 1) ? result.rows[i][1] : "";
            gd.nodes.push_back({
                name,
                name,
                ver,
                "standard",
                "",
                0
            });
        }
    }

    return gd;
}

const GraphData& resolve_graph(const QueryResult& result, GraphData& fallback_storage) {
    if (result.graph.has_value() && !result.graph->is_empty()) {
        return *result.graph;
    }
    fallback_storage = extract_fallback_graph(result);
    return fallback_storage;
}

} // anonymous namespace

std::string ResultFormatter::to_dot(const QueryResult& result) {
    GraphData fallback;
    const auto& gd = resolve_graph(result, fallback);

    std::ostringstream oss;
    std::string title = gd.title.empty() ? "G" : gd.title;
    std::string safe_title;
    for (char c : title) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') safe_title += c;
        else safe_title += '_';
    }
    if (safe_title.empty()) safe_title = "G";

    oss << "digraph " << safe_title << " {\n";
    oss << "  rankdir=TB;\n";
    oss << "  node [shape=box, style=\"filled,rounded\", fontname=\"Helvetica\", margin=\"0.2,0.1\"];\n";
    oss << "  edge [fontname=\"Helvetica\", fontsize=10];\n\n";

    if (gd.is_empty()) {
        oss << "  \"empty\" [label=\"(empty result set)\", fillcolor=\"#f0f4f8\", fontcolor=\"#666666\", color=\"#cfd8dc\"];\n";
        oss << "}\n";
        return oss.str();
    }

    for (const auto& node : gd.nodes) {
        std::string label = node.name.empty() ? node.id : node.name;
        if (!node.version.empty()) {
            label += "\\n" + node.version;
        }
        if (!node.details.empty()) {
            label += "\\n[" + node.details + "]";
        } else if (node.role == "root") {
            label += "\\n[Root App]";
        }

        std::string fillcolor = "#e1f5fe";
        std::string fontcolor = "#0d47a1";
        std::string bordercolor = "#81d4fa";

        if (node.role == "root") {
            fillcolor = "#2e78d2";
            fontcolor = "#ffffff";
            bordercolor = "#1a539e";
        } else if (node.role == "vulnerable") {
            fillcolor = "#ff4d4d";
            fontcolor = "#ffffff";
            bordercolor = "#cc0000";
        } else if (node.role == "transitive") {
            fillcolor = "#ffa500";
            fontcolor = "#ffffff";
            bordercolor = "#cc8400";
        }

        std::string node_id = node.name.empty() ? node.id : node.name;
        oss << "  \"" << escape_dot_string(node_id) << "\" [label=\"" 
            << escape_dot_string(label) << "\", fillcolor=\"" << fillcolor 
            << "\", fontcolor=\"" << fontcolor << "\", color=\"" << bordercolor << "\"];\n";
    }

    oss << "\n";

    for (const auto& edge : gd.edges) {
        oss << "  \"" << escape_dot_string(edge.from_id) << "\" -> \"" 
            << escape_dot_string(edge.to_id) << "\"";
        if (!edge.label.empty()) {
            oss << " [label=\"" << escape_dot_string(edge.label) << "\"]";
        }
        oss << ";\n";
    }

    oss << "}\n";
    return oss.str();
}

std::string ResultFormatter::to_mermaid(const QueryResult& result) {
    GraphData fallback;
    const auto& gd = resolve_graph(result, fallback);

    std::ostringstream oss;
    oss << "graph TD\n";

    if (gd.is_empty()) {
        oss << "    empty[\"(empty result set)\"]\n";
        return oss.str();
    }

    std::unordered_map<std::string, std::string> id_to_mermaid;
    for (const auto& node : gd.nodes) {
        std::string base = node.name.empty() ? node.id : node.name;
        std::string mid = sanitize_mermaid_id(base);
        id_to_mermaid[node.id] = mid;
        if (!node.name.empty()) {
            id_to_mermaid[node.name] = mid;
        }
    }

    oss << "    %% Nodes\n";
    for (const auto& node : gd.nodes) {
        std::string mid = id_to_mermaid[node.id];
        std::string label = node.name.empty() ? node.id : node.name;
        if (!node.version.empty()) {
            label += "@" + node.version;
        }
        if (!node.details.empty()) {
            label += " [" + node.details + "]";
        } else if (node.role == "root") {
            label += " (Root App)";
        }

        oss << "    " << mid << "[\"" << escape_mermaid_label(label) << "\"]\n";
    }

    if (!gd.edges.empty()) {
        oss << "\n    %% Edges\n";
        for (const auto& edge : gd.edges) {
            std::string from_mid = id_to_mermaid.count(edge.from_id) ? id_to_mermaid[edge.from_id] : sanitize_mermaid_id(edge.from_id);
            std::string to_mid = id_to_mermaid.count(edge.to_id) ? id_to_mermaid[edge.to_id] : sanitize_mermaid_id(edge.to_id);

            if (!edge.label.empty()) {
                oss << "    " << from_mid << " -->|" << edge.label << "| " << to_mid << "\n";
            } else {
                oss << "    " << from_mid << " --> " << to_mid << "\n";
            }
        }
    }

    oss << "\n    %% Security Impact Styles\n";
    for (const auto& node : gd.nodes) {
        std::string mid = id_to_mermaid[node.id];
        if (node.role == "root") {
            oss << "    style " << mid << " fill:#2e78d2,stroke:#1a539e,stroke-width:2px,color:#ffffff\n";
        } else if (node.role == "vulnerable") {
            oss << "    style " << mid << " fill:#ff4d4d,stroke:#cc0000,stroke-width:2px,color:#ffffff\n";
        } else if (node.role == "transitive") {
            oss << "    style " << mid << " fill:#ffa500,stroke:#cc8400,stroke-width:2px,color:#ffffff\n";
        } else {
            oss << "    style " << mid << " fill:#e1f5fe,stroke:#81d4fa,stroke-width:1px,color:#0d47a1\n";
        }
    }

    return oss.str();
}

} // namespace sbom_dsl
