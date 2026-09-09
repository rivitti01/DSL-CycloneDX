#include "sbom_dsl/ir/ir_printer.hpp"
#include "sbom_dsl/ast/ast_printer.hpp"
#include <sstream>

namespace sbom_dsl {

std::string_view ir_node_type_name(IRNodeType type) {
    switch (type) {
        case IRNodeType::Scan: return "IRScan";
        case IRNodeType::Filter: return "IRFilter";
        case IRNodeType::Project: return "IRProject";
        case IRNodeType::Sort: return "IRSort";
        case IRNodeType::Limit: return "IRLimit";
        case IRNodeType::HashJoin: return "IRHashJoin";
        case IRNodeType::GraphTraverse: return "IRGraphTraverse";
        case IRNodeType::BlastRadius: return "IRBlastRadius";
    }
    return "UnknownIR";
}

std::string_view graph_direction_name(GraphDirection dir) {
    switch (dir) {
        case GraphDirection::Forward: return "FORWARD";
        case GraphDirection::Reverse: return "REVERSE";
    }
    return "UNKNOWN_DIR";
}

std::string IRScan::description() const {
    std::string s = "Scan(collection=\"" + collection + "\"";
    if (bom_path) s += ", file=\"" + *bom_path + "\"";
    s += ")";
    return s;
}

std::string IRFilter::description() const {
    ASTPrinter p;
    std::string pred_str = predicate ? p.print(*predicate) : "true";
    while (!pred_str.empty() && pred_str.back() == '\n') pred_str.pop_back();
    return "Filter(predicate=[" + pred_str + "])";
}

std::string IRProject::description() const {
    std::string s = "Project(columns=[";
    if (projections.empty()) {
        s += "*";
    } else {
        for (size_t i = 0; i < projections.size(); ++i) {
            if (i > 0) s += ", ";
            s += projections[i];
        }
    }
    s += "])";
    return s;
}

std::string IRSort::description() const {
    return "Sort(column=\"" + column + "\", order=" + (ascending ? "ASC" : "DESC") + ")";
}

std::string IRLimit::description() const {
    return "Limit(count=" + std::to_string(limit) + ")";
}

std::string IRHashJoin::description() const {
    return "HashJoin(on left." + left_key + " == right." + right_key + ")";
}

std::string IRGraphTraverse::description() const {
    std::string s = "GraphTraverse(target=\"" + target + "\", direction=" + 
                    std::string(graph_direction_name(direction)) + 
                    ", transitive=" + (transitive ? "true" : "false");
    if (max_depth) s += ", max_depth=" + std::to_string(*max_depth);
    s += ")";
    return s;
}

std::string IRBlastRadius::description() const {
    return "BlastRadius(vulnerability_id=\"" + vulnerability_id + "\")";
}

void IRPrinter::print_node(const IRNode& node, std::ostringstream& oss, int indent) {
    for (int i = 0; i < indent; ++i) {
        oss << "  ";
    }
    oss << node.description() << "\n";

    switch (node.type()) {
        case IRNodeType::Scan:
            break;
        case IRNodeType::Filter: {
            const auto& n = static_cast<const IRFilter&>(node);
            if (n.child) print_node(*n.child, oss, indent + 1);
            break;
        }
        case IRNodeType::Project: {
            const auto& n = static_cast<const IRProject&>(node);
            if (n.child) print_node(*n.child, oss, indent + 1);
            break;
        }
        case IRNodeType::Sort: {
            const auto& n = static_cast<const IRSort&>(node);
            if (n.child) print_node(*n.child, oss, indent + 1);
            break;
        }
        case IRNodeType::Limit: {
            const auto& n = static_cast<const IRLimit&>(node);
            if (n.child) print_node(*n.child, oss, indent + 1);
            break;
        }
        case IRNodeType::HashJoin: {
            const auto& n = static_cast<const IRHashJoin&>(node);
            for (int i = 0; i < indent + 1; ++i) oss << "  ";
            oss << "Left Input:\n";
            if (n.left) print_node(*n.left, oss, indent + 2);
            for (int i = 0; i < indent + 1; ++i) oss << "  ";
            oss << "Right Input:\n";
            if (n.right) print_node(*n.right, oss, indent + 2);
            break;
        }
        case IRNodeType::GraphTraverse: {
            const auto& n = static_cast<const IRGraphTraverse&>(node);
            if (n.child) print_node(*n.child, oss, indent + 1);
            break;
        }
        case IRNodeType::BlastRadius: {
            const auto& n = static_cast<const IRBlastRadius&>(node);
            if (n.child) print_node(*n.child, oss, indent + 1);
            break;
        }
    }
}

std::string IRPrinter::print(const IRNode& node) {
    std::ostringstream oss;
    print_node(node, oss, 0);
    return oss.str();
}

std::string IRPrinter::print(const IRPlan& plan) {
    std::ostringstream oss;
    oss << "IR Execution Plan:\n";
    if (plan.bom_path) {
        oss << "  Target SBOM File: " << *plan.bom_path << "\n";
    }
    if (plan.root) {
        print_node(*plan.root, oss, 1);
    }
    return oss.str();
}

} // namespace sbom_dsl
