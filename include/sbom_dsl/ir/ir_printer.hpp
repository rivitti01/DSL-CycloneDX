#pragma once

#include "sbom_dsl/ir/ir.hpp"
#include <string>

namespace sbom_dsl {

class IRPrinter {
public:
    static std::string print(const IRNode& node);
    static std::string print(const IRPlan& plan);

private:
    static void print_node(const IRNode& node, std::ostringstream& oss, int indent);
};

} // namespace sbom_dsl
