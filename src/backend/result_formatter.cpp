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
    }
    return to_table(result);
}

std::string ResultFormatter::to_table(const QueryResult& result) {
    if (result.columns.empty()) {
        return "(empty result set, 0 rows)\n";
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

    std::ostringstream oss;

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

} // namespace sbom_dsl
