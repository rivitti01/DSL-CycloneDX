#pragma once

#include "sbom_dsl/backend/query_result.hpp"
#include <string>

namespace sbom_dsl {

enum class OutputFormat {
    Table,
    Json,
    Tree
};

class ResultFormatter {
public:
    static std::string format(const QueryResult& result, OutputFormat fmt = OutputFormat::Table);
    static std::string to_table(const QueryResult& result);
    static std::string to_json(const QueryResult& result);
    static std::string to_tree(const QueryResult& result);
};

} // namespace sbom_dsl
