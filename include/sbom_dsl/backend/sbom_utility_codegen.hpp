#pragma once

#include "sbom_dsl/ir/ir.hpp"
#include "sbom_dsl/backend/query_result.hpp"
#include "sbom_dsl/common/diagnostic.hpp"
#include <string>
#include <optional>

namespace sbom_dsl {

class SbomUtilityCodeGen {
public:
    static bool can_offload(const IRPlan& plan, std::string* reason = nullptr);
    static std::optional<std::string> generate_command(const IRPlan& plan, const std::string& default_file = "bom.json");
    static QueryResult execute_command(const std::string& command, DiagnosticEngine& diag);

private:
    static bool extract_where_filters(const ExpressionNode* expr, std::vector<std::pair<std::string, std::string>>& filters);
};

} // namespace sbom_dsl
