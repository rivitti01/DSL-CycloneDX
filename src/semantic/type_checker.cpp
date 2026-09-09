#include "sbom_dsl/semantic/type_checker.hpp"

namespace sbom_dsl {

TypeChecker::TypeChecker(DiagnosticEngine& diag)
    : diag_(diag), catalog_(SchemaCatalog::instance()) {}

bool TypeChecker::check(ASTNode& node) {
    node.accept(*this);
    return !diag_.has_errors();
}

DataType TypeChecker::infer_expression_type(ExpressionNode& expr) {
    last_inferred_type_ = DataType::Unknown;
    expr.accept(*this);
    return last_inferred_type_;
}

bool TypeChecker::are_types_compatible(DataType t1, DataType t2, BinaryOperator op) const {
    if (t1 == DataType::Unknown || t2 == DataType::Unknown) {
        return true; // Allow if unknown to avoid cascading false errors
    }

    // Logical operators require booleans
    if (op == BinaryOperator::And || op == BinaryOperator::Or) {
        return (t1 == DataType::Boolean && t2 == DataType::Boolean);
    }

    // CONTAINS, MATCHES, LIKE require strings
    if (op == BinaryOperator::Contains || op == BinaryOperator::Matches || op == BinaryOperator::Like) {
        return (t1 == DataType::String && t2 == DataType::String);
    }

    // Numerics can be compared with each other
    bool is_num1 = (t1 == DataType::Integer || t1 == DataType::Float);
    bool is_num2 = (t2 == DataType::Integer || t2 == DataType::Float);
    if (is_num1 && is_num2) {
        return true;
    }

    // Direct equality / inequality for same types
    if (t1 == t2) {
        return true;
    }

    return false;
}

void TypeChecker::visit(ProgramNode& node) {
    for (auto& stmt : node.statements) {
        stmt->accept(*this);
    }
}

void TypeChecker::visit(SelectStatement& node) {
    current_collection_ = node.collection;

    // Check collection exists
    if (!catalog_.is_valid_collection(node.collection)) {
        diag_.error(node.location, "Unknown collection '" + node.collection + 
                    "'. Valid collections are: components, vulnerabilities, dependencies, metadata.component, services");
    }

    // Check projections
    for (const auto& proj : node.projections) {
        if (!catalog_.is_valid_field(node.collection, proj)) {
            diag_.warning(node.location, "Field '" + proj + "' is not declared in CycloneDX schema for '" + 
                          node.collection + "' (will be resolved dynamically)");
        }
    }

    // Check WHERE clause
    if (node.where_clause) {
        DataType where_type = infer_expression_type(*node.where_clause);
        if (where_type != DataType::Boolean && where_type != DataType::Unknown) {
            diag_.error(node.where_clause->location, 
                        "WHERE clause must evaluate to a boolean expression, found " + 
                        std::string(data_type_name(where_type)));
        }
    }

    // Check ORDER BY
    if (node.order_by) {
        if (!catalog_.is_valid_field(node.collection, node.order_by->column)) {
            diag_.warning(node.location, "ORDER BY column '" + node.order_by->column + 
                          "' is not a standard field of '" + node.collection + "'");
        }
    }

    // Check LIMIT
    if (node.limit.has_value() && *node.limit == 0) {
        diag_.error(node.location, "LIMIT must be greater than 0");
    }
}

void TypeChecker::visit(WhoUsesStatement& node) {
    if (node.target_component.empty()) {
        diag_.error(node.location, "Target component in 'WHO USES' cannot be empty");
    }
}

void TypeChecker::visit(FindVulnerableStatement& node) {
    current_collection_ = "vulnerabilities";

    if (node.where_clause) {
        DataType where_type = infer_expression_type(*node.where_clause);
        if (where_type != DataType::Boolean && where_type != DataType::Unknown) {
            diag_.error(node.where_clause->location, 
                        "WHERE clause in FIND VULNERABLE must evaluate to a boolean expression");
        }
    }
}

void TypeChecker::visit(ShowTreeStatement& node) {
    if (node.max_depth.has_value() && *node.max_depth == 0) {
        diag_.error(node.location, "DEPTH must be greater than 0");
    }
}

void TypeChecker::visit(BlastRadiusStatement& node) {
    if (node.vulnerability_id.empty()) {
        diag_.error(node.location, "Vulnerability ID in 'FIND BLAST RADIUS OF' cannot be empty");
    }
}

void TypeChecker::visit(BinaryOpExpr& node) {
    DataType left_type = infer_expression_type(*node.left);
    DataType right_type = infer_expression_type(*node.right);

    if (!are_types_compatible(left_type, right_type, node.op)) {
        diag_.error(node.location, "Type mismatch in operator '" + 
                    std::string(binary_op_to_string(node.op)) + "': cannot compare " + 
                    std::string(data_type_name(left_type)) + " with " + 
                    std::string(data_type_name(right_type)));
    }

    // All binary ops in our grammar yield a boolean
    last_inferred_type_ = DataType::Boolean;
}

void TypeChecker::visit(UnaryOpExpr& node) {
    DataType op_type = infer_expression_type(*node.operand);
    if (op_type != DataType::Boolean && op_type != DataType::Unknown) {
        diag_.error(node.location, "Operand of NOT must be a boolean expression, found " + 
                    std::string(data_type_name(op_type)));
    }
    last_inferred_type_ = DataType::Boolean;
}

void TypeChecker::visit(ColumnRefExpr& node) {
    std::string field = node.full_path();
    DataType dt = catalog_.get_field_type(current_collection_, field);
    last_inferred_type_ = dt;
}

void TypeChecker::visit(LiteralExpr& node) {
    std::visit([this](const auto& v) {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, std::string>) {
            last_inferred_type_ = DataType::String;
        } else if constexpr (std::is_same_v<T, int64_t>) {
            last_inferred_type_ = DataType::Integer;
        } else if constexpr (std::is_same_v<T, double>) {
            last_inferred_type_ = DataType::Float;
        } else if constexpr (std::is_same_v<T, bool>) {
            last_inferred_type_ = DataType::Boolean;
        } else if constexpr (std::is_same_v<T, SeverityLevel>) {
            last_inferred_type_ = DataType::Severity;
        }
    }, node.value);
}

} // namespace sbom_dsl
