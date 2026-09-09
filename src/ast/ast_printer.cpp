#include "sbom_dsl/ast/ast_printer.hpp"
#include <algorithm>

namespace sbom_dsl {

std::string_view binary_op_to_string(BinaryOperator op) {
    switch (op) {
        case BinaryOperator::Equal: return "=";
        case BinaryOperator::NotEqual: return "!=";
        case BinaryOperator::Less: return "<";
        case BinaryOperator::LessEqual: return "<=";
        case BinaryOperator::Greater: return ">";
        case BinaryOperator::GreaterEqual: return ">=";
        case BinaryOperator::And: return "AND";
        case BinaryOperator::Or: return "OR";
        case BinaryOperator::Contains: return "CONTAINS";
        case BinaryOperator::Matches: return "MATCHES";
        case BinaryOperator::Like: return "LIKE";
    }
    return "UNKNOWN_OP";
}

std::string_view unary_op_to_string(UnaryOperator op) {
    switch (op) {
        case UnaryOperator::Not: return "NOT";
    }
    return "UNKNOWN_UNARY";
}

std::string_view severity_to_string(SeverityLevel sev) {
    switch (sev) {
        case SeverityLevel::Critical: return "CRITICAL";
        case SeverityLevel::High: return "HIGH";
        case SeverityLevel::Medium: return "MEDIUM";
        case SeverityLevel::Low: return "LOW";
        case SeverityLevel::Info: return "INFO";
        case SeverityLevel::None: return "NONE";
    }
    return "UNKNOWN_SEV";
}

std::optional<SeverityLevel> severity_from_string(std::string_view str) {
    std::string upper;
    upper.reserve(str.size());
    for (char c : str) {
        upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }

    if (upper == "CRITICAL") return SeverityLevel::Critical;
    if (upper == "HIGH") return SeverityLevel::High;
    if (upper == "MEDIUM") return SeverityLevel::Medium;
    if (upper == "LOW") return SeverityLevel::Low;
    if (upper == "INFO") return SeverityLevel::Info;
    if (upper == "NONE") return SeverityLevel::None;
    return std::nullopt;
}

std::string_view assert_target_to_string(AssertTarget target) {
    switch (target) {
        case AssertTarget::Vulnerabilities: return "VULNERABILITIES";
        case AssertTarget::Components: return "COMPONENTS";
        case AssertTarget::Libraries: return "LIBRARIES";
    }
    return "UNKNOWN_TARGET";
}

bool is_aggregate_expression(std::string_view expr, std::string* func_name, std::string* arg) {
    if (expr.size() < 7) return false;
    std::string upper;
    upper.reserve(expr.size());
    for (char c : expr) {
        upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }

    if (upper.rfind("COUNT(", 0) == 0 && upper.back() == ')') {
        if (func_name) *func_name = "COUNT";
        std::string inner = std::string(expr.substr(6, expr.size() - 7));
        size_t s = inner.find_first_not_of(" \t\r\n");
        size_t e = inner.find_last_not_of(" \t\r\n");
        if (s != std::string::npos && e != std::string::npos) {
            inner = inner.substr(s, e - s + 1);
        } else {
            inner.clear();
        }
        if (arg) *arg = inner;
        return true;
    }
    return false;
}

bool SelectStatement::has_aggregates() const {
    for (const auto& p : projections) {
        if (is_aggregate_expression(p)) return true;
    }
    return false;
}

std::string ColumnRefExpr::full_path() const {
    std::string res;
    for (size_t i = 0; i < path.size(); ++i) {
        if (i > 0) res += ".";
        res += path[i];
    }
    return res;
}

std::string LiteralExpr::value_as_string() const {
    return std::visit([](const auto& v) -> std::string {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, std::string>) {
            return "\"" + v + "\"";
        } else if constexpr (std::is_same_v<T, int64_t>) {
            return std::to_string(v);
        } else if constexpr (std::is_same_v<T, double>) {
            return std::to_string(v);
        } else if constexpr (std::is_same_v<T, bool>) {
            return v ? "true" : "false";
        } else if constexpr (std::is_same_v<T, SeverityLevel>) {
            return std::string(severity_to_string(v));
        }
        return "";
    }, value);
}

// Accept methods
void BinaryOpExpr::accept(ASTVisitor& visitor) { visitor.visit(*this); }
void UnaryOpExpr::accept(ASTVisitor& visitor) { visitor.visit(*this); }
void ColumnRefExpr::accept(ASTVisitor& visitor) { visitor.visit(*this); }
void LiteralExpr::accept(ASTVisitor& visitor) { visitor.visit(*this); }
void SelectStatement::accept(ASTVisitor& visitor) { visitor.visit(*this); }
void WhoUsesStatement::accept(ASTVisitor& visitor) { visitor.visit(*this); }
void FindVulnerableStatement::accept(ASTVisitor& visitor) { visitor.visit(*this); }
void ShowTreeStatement::accept(ASTVisitor& visitor) { visitor.visit(*this); }
void BlastRadiusStatement::accept(ASTVisitor& visitor) { visitor.visit(*this); }
void AssertStatement::accept(ASTVisitor& visitor) { visitor.visit(*this); }
void ProgramNode::accept(ASTVisitor& visitor) { visitor.visit(*this); }

// ASTPrinter implementation
std::string ASTPrinter::print(ASTNode& node) {
    oss_.str("");
    oss_.clear();
    indent_level_ = 0;
    node.accept(*this);
    return oss_.str();
}

void ASTPrinter::indent() { ++indent_level_; }
void ASTPrinter::dedent() { if (indent_level_ > 0) --indent_level_; }

void ASTPrinter::write_indent() {
    for (int i = 0; i < indent_level_; ++i) {
        oss_ << "  ";
    }
}

void ASTPrinter::visit(ProgramNode& node) {
    write_indent();
    oss_ << "Program (" << node.statements.size() << " statements):\n";
    indent();
    for (const auto& stmt : node.statements) {
        stmt->accept(*this);
    }
    dedent();
}

void ASTPrinter::visit(SelectStatement& node) {
    write_indent();
    oss_ << "SelectStatement:\n";
    indent();
    write_indent();
    oss_ << "Projections: ";
    if (node.projections.empty()) {
        oss_ << "*\n";
    } else {
        for (size_t i = 0; i < node.projections.size(); ++i) {
            if (i > 0) oss_ << ", ";
            oss_ << node.projections[i];
        }
        oss_ << "\n";
    }
    write_indent();
    oss_ << "Collection: " << node.collection << "\n";
    if (node.bom_path) {
        write_indent();
        oss_ << "File: " << *node.bom_path << "\n";
    }
    if (node.where_clause) {
        write_indent();
        oss_ << "Where:\n";
        indent();
        node.where_clause->accept(*this);
        dedent();
    }
    if (!node.group_by.empty()) {
        write_indent();
        oss_ << "GroupBy: ";
        for (size_t i = 0; i < node.group_by.size(); ++i) {
            if (i > 0) oss_ << ", ";
            oss_ << node.group_by[i];
        }
        oss_ << "\n";
    }
    if (node.order_by) {
        write_indent();
        oss_ << "OrderBy: " << node.order_by->column 
            << (node.order_by->ascending ? " ASC" : " DESC") << "\n";
    }
    if (node.limit) {
        write_indent();
        oss_ << "Limit: " << *node.limit << "\n";
    }
    dedent();
}

void ASTPrinter::visit(WhoUsesStatement& node) {
    write_indent();
    oss_ << "WhoUsesStatement:\n";
    indent();
    write_indent();
    oss_ << "Target: \"" << node.target_component << "\"\n";
    write_indent();
    oss_ << "Mode: " << (node.is_transitive ? "TRANSITIVE" : "DIRECT") << "\n";
    if (node.bom_path) {
        write_indent();
        oss_ << "File: " << *node.bom_path << "\n";
    }
    dedent();
}

void ASTPrinter::visit(FindVulnerableStatement& node) {
    write_indent();
    oss_ << "FindVulnerableStatement:\n";
    indent();
    write_indent();
    oss_ << "Target: " << (node.libraries_only ? "LIBRARIES" : "COMPONENTS") << "\n";
    if (node.severity_level) {
        write_indent();
        oss_ << "Severity: " 
            << (node.severity_op ? binary_op_to_string(*node.severity_op) : "=")
            << " " << severity_to_string(*node.severity_level) << "\n";
    }
    if (node.where_clause) {
        write_indent();
        oss_ << "Where:\n";
        indent();
        node.where_clause->accept(*this);
        dedent();
    }
    if (node.bom_path) {
        write_indent();
        oss_ << "File: " << *node.bom_path << "\n";
    }
    dedent();
}

void ASTPrinter::visit(ShowTreeStatement& node) {
    write_indent();
    oss_ << "ShowTreeStatement:\n";
    indent();
    if (node.root_component) {
        write_indent();
        oss_ << "Root: \"" << *node.root_component << "\"\n";
    }
    if (node.max_depth) {
        write_indent();
        oss_ << "MaxDepth: " << *node.max_depth << "\n";
    }
    if (node.bom_path) {
        write_indent();
        oss_ << "File: " << *node.bom_path << "\n";
    }
    dedent();
}

void ASTPrinter::visit(BlastRadiusStatement& node) {
    write_indent();
    oss_ << "BlastRadiusStatement:\n";
    indent();
    write_indent();
    oss_ << "VulnerabilityId: \"" << node.vulnerability_id << "\"\n";
    if (node.bom_path) {
        write_indent();
        oss_ << "File: " << *node.bom_path << "\n";
    }
    dedent();
}

void ASTPrinter::visit(AssertStatement& node) {
    write_indent();
    oss_ << "AssertStatement:\n";
    indent();
    write_indent();
    oss_ << "Target: " << assert_target_to_string(node.target) << "\n";
    if (node.severity_level) {
        write_indent();
        oss_ << "Severity: " 
            << (node.severity_op ? binary_op_to_string(*node.severity_op) : "=")
            << " " << severity_to_string(*node.severity_level) << "\n";
    } else if (node.score_threshold) {
        write_indent();
        oss_ << "Score: "
            << (node.severity_op ? binary_op_to_string(*node.severity_op) : "=")
            << " " << *node.score_threshold << "\n";
    }
    if (node.where_clause) {
        write_indent();
        oss_ << "Where:\n";
        indent();
        node.where_clause->accept(*this);
        dedent();
    }
    if (node.bom_path) {
        write_indent();
        oss_ << "File: " << *node.bom_path << "\n";
    }
    dedent();
}

void ASTPrinter::visit(BinaryOpExpr& node) {
    write_indent();
    oss_ << "BinaryOp (" << binary_op_to_string(node.op) << "):\n";
    indent();
    node.left->accept(*this);
    node.right->accept(*this);
    dedent();
}

void ASTPrinter::visit(UnaryOpExpr& node) {
    write_indent();
    oss_ << "UnaryOp (" << unary_op_to_string(node.op) << "):\n";
    indent();
    node.operand->accept(*this);
    dedent();
}

void ASTPrinter::visit(ColumnRefExpr& node) {
    write_indent();
    oss_ << "ColumnRef: " << node.full_path() << "\n";
}

void ASTPrinter::visit(LiteralExpr& node) {
    write_indent();
    oss_ << "Literal: " << node.value_as_string() << "\n";
}

} // namespace sbom_dsl
