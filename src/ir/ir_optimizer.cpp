#include "sbom_dsl/ir/ir_optimizer.hpp"
#include "sbom_dsl/semantic/schema_catalog.hpp"
#include <algorithm>
#include <cctype>
#include <regex>

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

int severity_rank(SeverityLevel s) {
    switch (s) {
        case SeverityLevel::None: return 0;
        case SeverityLevel::Info: return 1;
        case SeverityLevel::Low: return 2;
        case SeverityLevel::Medium: return 3;
        case SeverityLevel::High: return 4;
        case SeverityLevel::Critical: return 5;
    }
    return 0;
}

} // anonymous namespace

std::unique_ptr<ExpressionNode> clone_expression(const ExpressionNode* expr) {
    if (!expr) return nullptr;

    if (const auto* bin = dynamic_cast<const BinaryOpExpr*>(expr)) {
        return std::make_unique<BinaryOpExpr>(
            bin->op,
            clone_expression(bin->left.get()),
            clone_expression(bin->right.get()),
            bin->location
        );
    }
    if (const auto* un = dynamic_cast<const UnaryOpExpr*>(expr)) {
        return std::make_unique<UnaryOpExpr>(
            un->op,
            clone_expression(un->operand.get()),
            un->location
        );
    }
    if (const auto* col = dynamic_cast<const ColumnRefExpr*>(expr)) {
        return std::make_unique<ColumnRefExpr>(col->path, col->location);
    }
    if (const auto* lit = dynamic_cast<const LiteralExpr*>(expr)) {
        return std::make_unique<LiteralExpr>(lit->value, lit->location);
    }
    return nullptr;
}

std::unique_ptr<IRNode> clone_ir_node(const IRNode* node) {
    if (!node) return nullptr;

    switch (node->type()) {
        case IRNodeType::Scan: {
            const auto* s = static_cast<const IRScan*>(node);
            return std::make_unique<IRScan>(s->collection, s->bom_path);
        }
        case IRNodeType::Filter: {
            const auto* f = static_cast<const IRFilter*>(node);
            return std::make_unique<IRFilter>(
                clone_ir_node(f->child.get()),
                clone_expression(f->predicate.get())
            );
        }
        case IRNodeType::Project: {
            const auto* p = static_cast<const IRProject*>(node);
            return std::make_unique<IRProject>(
                clone_ir_node(p->child.get()),
                p->projections
            );
        }
        case IRNodeType::Sort: {
            const auto* s = static_cast<const IRSort*>(node);
            return std::make_unique<IRSort>(
                clone_ir_node(s->child.get()),
                s->column,
                s->ascending
            );
        }
        case IRNodeType::Limit: {
            const auto* l = static_cast<const IRLimit*>(node);
            return std::make_unique<IRLimit>(
                clone_ir_node(l->child.get()),
                l->limit
            );
        }
        case IRNodeType::HashJoin: {
            const auto* j = static_cast<const IRHashJoin*>(node);
            return std::make_unique<IRHashJoin>(
                clone_ir_node(j->left.get()),
                clone_ir_node(j->right.get()),
                j->left_key,
                j->right_key
            );
        }
        case IRNodeType::GraphTraverse: {
            const auto* g = static_cast<const IRGraphTraverse*>(node);
            return std::make_unique<IRGraphTraverse>(
                clone_ir_node(g->child.get()),
                g->target,
                g->direction,
                g->transitive,
                g->max_depth
            );
        }
        case IRNodeType::BlastRadius: {
            const auto* b = static_cast<const IRBlastRadius*>(node);
            return std::make_unique<IRBlastRadius>(
                clone_ir_node(b->child.get()),
                b->vulnerability_id
            );
        }
        case IRNodeType::Aggregate: {
            const auto* a = static_cast<const IRAggregate*>(node);
            return std::make_unique<IRAggregate>(
                clone_ir_node(a->child.get()),
                a->group_by_columns,
                a->aggregates
            );
        }
    }
    return nullptr;
}

IRPlan clone_ir_plan(const IRPlan& plan) {
    IRPlan cloned;
    cloned.bom_path = plan.bom_path;
    cloned.is_assertion = plan.is_assertion;
    cloned.assertion_title = plan.assertion_title;
    cloned.root = clone_ir_node(plan.root.get());
    return cloned;
}

std::vector<std::unique_ptr<ExpressionNode>> split_conjunction(const ExpressionNode* expr) {
    std::vector<std::unique_ptr<ExpressionNode>> conjuncts;
    if (!expr) return conjuncts;

    if (const auto* bin = dynamic_cast<const BinaryOpExpr*>(expr)) {
        if (bin->op == BinaryOperator::And) {
            auto left = split_conjunction(bin->left.get());
            auto right = split_conjunction(bin->right.get());
            conjuncts.insert(conjuncts.end(),
                             std::make_move_iterator(left.begin()),
                             std::make_move_iterator(left.end()));
            conjuncts.insert(conjuncts.end(),
                             std::make_move_iterator(right.begin()),
                             std::make_move_iterator(right.end()));
            return conjuncts;
        }
    }

    conjuncts.push_back(clone_expression(expr));
    return conjuncts;
}

std::unique_ptr<ExpressionNode> combine_conjunction(std::vector<std::unique_ptr<ExpressionNode>> conjuncts, SourceLocation loc) {
    if (conjuncts.empty()) return nullptr;
    if (conjuncts.size() == 1) return std::move(conjuncts[0]);

    std::unique_ptr<ExpressionNode> result = std::move(conjuncts[0]);
    for (size_t i = 1; i < conjuncts.size(); ++i) {
        result = std::make_unique<BinaryOpExpr>(
            BinaryOperator::And,
            std::move(result),
            std::move(conjuncts[i]),
            loc
        );
    }
    return result;
}

static void collect_columns(const ExpressionNode& expr, std::unordered_set<std::string>& cols) {
    if (const auto* col = dynamic_cast<const ColumnRefExpr*>(&expr)) {
        cols.insert(col->full_path());
        if (!col->path.empty()) {
            cols.insert(col->path[0]);
            cols.insert(col->path.back());
        }
    } else if (const auto* bin = dynamic_cast<const BinaryOpExpr*>(&expr)) {
        if (bin->left) collect_columns(*bin->left, cols);
        if (bin->right) collect_columns(*bin->right, cols);
    } else if (const auto* un = dynamic_cast<const UnaryOpExpr*>(&expr)) {
        if (un->operand) collect_columns(*un->operand, cols);
    }
}

std::unordered_set<std::string> get_referenced_columns(const ExpressionNode& expr) {
    std::unordered_set<std::string> cols;
    collect_columns(expr, cols);
    return cols;
}

std::unordered_set<std::string> get_produced_attributes(const IRNode& node) {
    std::unordered_set<std::string> attrs;

    switch (node.type()) {
        case IRNodeType::Scan: {
            const auto& scan = static_cast<const IRScan&>(node);
            if (scan.collection == "components") {
                attrs = {"name", "version", "type", "bom-ref", "purl", "description",
                         "scope", "licenses", "hashes", "supplier", "author"};
            } else if (scan.collection == "vulnerabilities") {
                attrs = {"id", "vuln_id", "source", "ratings", "ratings.severity", "ratings.score",
                         "severity", "score", "cvss-severity", "cwe", "cwes", "description",
                         "detail", "recommendation", "affects", "analysis"};
            } else if (scan.collection == "dependencies") {
                attrs = {"ref", "dependsOn"};
            } else if (scan.collection == "metadata.component") {
                attrs = {"name", "version", "type", "bom-ref", "purl", "description"};
            } else if (scan.collection == "services") {
                attrs = {"name", "version", "bom-ref", "endpoints", "authenticated"};
            }
            break;
        }
        case IRNodeType::Filter: {
            const auto& f = static_cast<const IRFilter&>(node);
            if (f.child) return get_produced_attributes(*f.child);
            break;
        }
        case IRNodeType::Sort: {
            const auto& s = static_cast<const IRSort&>(node);
            if (s.child) return get_produced_attributes(*s.child);
            break;
        }
        case IRNodeType::Limit: {
            const auto& l = static_cast<const IRLimit&>(node);
            if (l.child) return get_produced_attributes(*l.child);
            break;
        }
        case IRNodeType::HashJoin: {
            const auto& j = static_cast<const IRHashJoin&>(node);
            if (j.left) {
                auto la = get_produced_attributes(*j.left);
                attrs.insert(la.begin(), la.end());
            }
            if (j.right) {
                auto ra = get_produced_attributes(*j.right);
                attrs.insert(ra.begin(), ra.end());
            }
            break;
        }
        case IRNodeType::GraphTraverse: {
            attrs = {"ref", "depth"};
            break;
        }
        case IRNodeType::BlastRadius: {
            attrs = {"vulnerability_id", "severity", "score", "total_components",
                     "directly_affected_components", "transitively_affected_components",
                     "impact_percentage", "root_application_affected"};
            break;
        }
        case IRNodeType::Aggregate: {
            const auto& a = static_cast<const IRAggregate&>(node);
            for (const auto& col : a.group_by_columns) {
                attrs.insert(col);
            }
            for (const auto& f : a.aggregates) {
                attrs.insert(f.result_column);
            }
            break;
        }
        case IRNodeType::Project: {
            const auto& p = static_cast<const IRProject&>(node);
            if (p.projections.empty() && p.child) {
                return get_produced_attributes(*p.child);
            }
            attrs.insert(p.projections.begin(), p.projections.end());
            break;
        }
    }
    return attrs;
}

bool IROptimizer::is_true_literal(const ExpressionNode* expr) {
    if (!expr) return false;
    const auto* lit = dynamic_cast<const LiteralExpr*>(expr);
    return lit && std::holds_alternative<bool>(lit->value) && std::get<bool>(lit->value) == true;
}

bool IROptimizer::is_false_literal(const ExpressionNode* expr) {
    if (!expr) return false;
    const auto* lit = dynamic_cast<const LiteralExpr*>(expr);
    return lit && std::holds_alternative<bool>(lit->value) && std::get<bool>(lit->value) == false;
}

std::unique_ptr<ExpressionNode> IROptimizer::evaluate_binary_literals(
    BinaryOperator op,
    const LiteralExpr& left,
    const LiteralExpr& right,
    SourceLocation loc
) {
    // 1. Both are numeric (int64_t or double)
    bool left_num = std::holds_alternative<int64_t>(left.value) || std::holds_alternative<double>(left.value);
    bool right_num = std::holds_alternative<int64_t>(right.value) || std::holds_alternative<double>(right.value);

    if (left_num && right_num) {
        double d_left = std::holds_alternative<int64_t>(left.value)
                            ? static_cast<double>(std::get<int64_t>(left.value))
                            : std::get<double>(left.value);
        double d_right = std::holds_alternative<int64_t>(right.value)
                             ? static_cast<double>(std::get<int64_t>(right.value))
                             : std::get<double>(right.value);

        bool res = false;
        switch (op) {
            case BinaryOperator::Equal: res = (d_left == d_right); break;
            case BinaryOperator::NotEqual: res = (d_left != d_right); break;
            case BinaryOperator::Less: res = (d_left < d_right); break;
            case BinaryOperator::LessEqual: res = (d_left <= d_right); break;
            case BinaryOperator::Greater: res = (d_left > d_right); break;
            case BinaryOperator::GreaterEqual: res = (d_left >= d_right); break;
            default: return nullptr;
        }
        return std::make_unique<LiteralExpr>(res, loc);
    }

    // 2. Both are strings
    if (std::holds_alternative<std::string>(left.value) && std::holds_alternative<std::string>(right.value)) {
        const std::string& s_left = std::get<std::string>(left.value);
        const std::string& s_right = std::get<std::string>(right.value);

        bool res = false;
        switch (op) {
            case BinaryOperator::Equal: res = (s_left == s_right); break;
            case BinaryOperator::NotEqual: res = (s_left != s_right); break;
            case BinaryOperator::Less: res = (s_left < s_right); break;
            case BinaryOperator::LessEqual: res = (s_left <= s_right); break;
            case BinaryOperator::Greater: res = (s_left > s_right); break;
            case BinaryOperator::GreaterEqual: res = (s_left >= s_right); break;
            case BinaryOperator::Contains: res = case_insensitive_contains(s_left, s_right); break;
            case BinaryOperator::Like: {
                try {
                    std::regex re(sql_like_to_regex(s_right), std::regex_constants::icase);
                    res = std::regex_match(s_left, re);
                } catch (...) {
                    return nullptr;
                }
                break;
            }
            case BinaryOperator::Matches: {
                try {
                    std::regex re(s_right, std::regex_constants::icase);
                    res = std::regex_search(s_left, re);
                } catch (...) {
                    return nullptr;
                }
                break;
            }
            default: return nullptr;
        }
        return std::make_unique<LiteralExpr>(res, loc);
    }

    // 3. Both are booleans
    if (std::holds_alternative<bool>(left.value) && std::holds_alternative<bool>(right.value)) {
        bool b_left = std::get<bool>(left.value);
        bool b_right = std::get<bool>(right.value);

        bool res = false;
        switch (op) {
            case BinaryOperator::Equal: res = (b_left == b_right); break;
            case BinaryOperator::NotEqual: res = (b_left != b_right); break;
            case BinaryOperator::And: res = (b_left && b_right); break;
            case BinaryOperator::Or: res = (b_left || b_right); break;
            default: return nullptr;
        }
        return std::make_unique<LiteralExpr>(res, loc);
    }

    // 4. Both are SeverityLevel
    if (std::holds_alternative<SeverityLevel>(left.value) && std::holds_alternative<SeverityLevel>(right.value)) {
        int r_left = severity_rank(std::get<SeverityLevel>(left.value));
        int r_right = severity_rank(std::get<SeverityLevel>(right.value));

        bool res = false;
        switch (op) {
            case BinaryOperator::Equal: res = (r_left == r_right); break;
            case BinaryOperator::NotEqual: res = (r_left != r_right); break;
            case BinaryOperator::Less: res = (r_left < r_right); break;
            case BinaryOperator::LessEqual: res = (r_left <= r_right); break;
            case BinaryOperator::Greater: res = (r_left > r_right); break;
            case BinaryOperator::GreaterEqual: res = (r_left >= r_right); break;
            default: return nullptr;
        }
        return std::make_unique<LiteralExpr>(res, loc);
    }

    // Incompatible types
    if (op == BinaryOperator::Equal) return std::make_unique<LiteralExpr>(false, loc);
    if (op == BinaryOperator::NotEqual) return std::make_unique<LiteralExpr>(true, loc);

    return nullptr;
}

std::unique_ptr<ExpressionNode> IROptimizer::fold_expression(std::unique_ptr<ExpressionNode> expr) {
    if (!expr) return nullptr;

    if (auto* bin = dynamic_cast<BinaryOpExpr*>(expr.get())) {
        bin->left = fold_expression(std::move(bin->left));
        bin->right = fold_expression(std::move(bin->right));

        // Evaluate two literals
        auto* lit_l = dynamic_cast<LiteralExpr*>(bin->left.get());
        auto* lit_r = dynamic_cast<LiteralExpr*>(bin->right.get());
        if (lit_l && lit_r) {
            auto folded_lit = evaluate_binary_literals(bin->op, *lit_l, *lit_r, bin->location);
            if (folded_lit) return folded_lit;
        }

        // Boolean identity rules
        if (bin->op == BinaryOperator::And) {
            if (is_true_literal(bin->left.get())) return std::move(bin->right);
            if (is_true_literal(bin->right.get())) return std::move(bin->left);
            if (is_false_literal(bin->left.get()) || is_false_literal(bin->right.get())) {
                return std::make_unique<LiteralExpr>(false, bin->location);
            }
        }

        if (bin->op == BinaryOperator::Or) {
            if (is_false_literal(bin->left.get())) return std::move(bin->right);
            if (is_false_literal(bin->right.get())) return std::move(bin->left);
            if (is_true_literal(bin->left.get()) || is_true_literal(bin->right.get())) {
                return std::make_unique<LiteralExpr>(true, bin->location);
            }
        }

        // Reflexive column comparison: col == col -> true, col != col -> false
        auto* col_l = dynamic_cast<ColumnRefExpr*>(bin->left.get());
        auto* col_r = dynamic_cast<ColumnRefExpr*>(bin->right.get());
        if (col_l && col_r && col_l->full_path() == col_r->full_path()) {
            if (bin->op == BinaryOperator::Equal || bin->op == BinaryOperator::LessEqual || bin->op == BinaryOperator::GreaterEqual) {
                return std::make_unique<LiteralExpr>(true, bin->location);
            }
            if (bin->op == BinaryOperator::NotEqual || bin->op == BinaryOperator::Less || bin->op == BinaryOperator::Greater) {
                return std::make_unique<LiteralExpr>(false, bin->location);
            }
        }

        return expr;
    }

    if (auto* un = dynamic_cast<UnaryOpExpr*>(expr.get())) {
        un->operand = fold_expression(std::move(un->operand));
        if (un->op == UnaryOperator::Not) {
            if (is_true_literal(un->operand.get())) {
                return std::make_unique<LiteralExpr>(false, un->location);
            }
            if (is_false_literal(un->operand.get())) {
                return std::make_unique<LiteralExpr>(true, un->location);
            }
            // Double negation elimination: NOT(NOT(x)) -> x
            if (auto* inner_un = dynamic_cast<UnaryOpExpr*>(un->operand.get())) {
                if (inner_un->op == UnaryOperator::Not) {
                    return fold_expression(std::move(inner_un->operand));
                }
            }
        }
        return expr;
    }

    return expr;
}

std::unique_ptr<IRNode> IROptimizer::fold_constants(std::unique_ptr<IRNode> node) {
    if (!node) return nullptr;

    switch (node->type()) {
        case IRNodeType::Scan:
            return node;

        case IRNodeType::Filter: {
            auto* f = static_cast<IRFilter*>(node.get());
            if (f->child) {
                f->child = fold_constants(std::move(f->child));
            }
            if (f->predicate) {
                f->predicate = fold_expression(std::move(f->predicate));
            }

            // Tautological filter elimination: Filter(true, child) -> child
            if (!f->predicate || is_true_literal(f->predicate.get())) {
                return std::move(f->child);
            }

            // Merge consecutive filters: Filter(P1, Filter(P2, Child)) -> Filter(P1 AND P2, Child)
            if (f->child && f->child->type() == IRNodeType::Filter) {
                auto inner_filter = std::unique_ptr<IRFilter>(static_cast<IRFilter*>(f->child.release()));
                auto combined = std::make_unique<BinaryOpExpr>(
                    BinaryOperator::And,
                    std::move(f->predicate),
                    std::move(inner_filter->predicate),
                    SourceLocation{}
                );
                f->predicate = fold_expression(std::move(combined));
                f->child = std::move(inner_filter->child);

                if (!f->predicate || is_true_literal(f->predicate.get())) {
                    return std::move(f->child);
                }
            }

            return node;
        }

        case IRNodeType::Project: {
            auto* p = static_cast<IRProject*>(node.get());
            if (p->child) p->child = fold_constants(std::move(p->child));
            return node;
        }

        case IRNodeType::Sort: {
            auto* s = static_cast<IRSort*>(node.get());
            if (s->child) s->child = fold_constants(std::move(s->child));
            return node;
        }

        case IRNodeType::Limit: {
            auto* l = static_cast<IRLimit*>(node.get());
            if (l->child) l->child = fold_constants(std::move(l->child));
            return node;
        }

        case IRNodeType::HashJoin: {
            auto* j = static_cast<IRHashJoin*>(node.get());
            if (j->left) j->left = fold_constants(std::move(j->left));
            if (j->right) j->right = fold_constants(std::move(j->right));
            return node;
        }

        case IRNodeType::GraphTraverse: {
            auto* g = static_cast<IRGraphTraverse*>(node.get());
            if (g->child) g->child = fold_constants(std::move(g->child));
            return node;
        }

        case IRNodeType::BlastRadius: {
            auto* b = static_cast<IRBlastRadius*>(node.get());
            if (b->child) b->child = fold_constants(std::move(b->child));
            return node;
        }

        case IRNodeType::Aggregate: {
            auto* a = static_cast<IRAggregate*>(node.get());
            if (a->child) a->child = fold_constants(std::move(a->child));
            return node;
        }
    }

    return node;
}

std::unique_ptr<IRNode> IROptimizer::pushdown_predicates(std::unique_ptr<IRNode> node) {
    if (!node) return nullptr;

    switch (node->type()) {
        case IRNodeType::Scan:
            return node;

        case IRNodeType::Filter: {
            auto* filter = static_cast<IRFilter*>(node.get());
            if (filter->child) {
                filter->child = pushdown_predicates(std::move(filter->child));
            }

            // Pushdown rule 1: Push Filter past Sort: Filter(P, Sort(child)) -> Sort(Filter(P, child))
            if (filter->child && filter->child->type() == IRNodeType::Sort) {
                auto sort = std::unique_ptr<IRSort>(static_cast<IRSort*>(filter->child.release()));
                auto pushed = std::make_unique<IRFilter>(std::move(sort->child), std::move(filter->predicate));
                sort->child = pushdown_predicates(std::move(pushed));
                return sort;
            }

            // Pushdown rule 2: Push Filter past HashJoin: Filter(P, HashJoin(left, right))
            if (filter->child && filter->child->type() == IRNodeType::HashJoin) {
                auto join = std::unique_ptr<IRHashJoin>(static_cast<IRHashJoin*>(filter->child.release()));

                auto conjuncts = split_conjunction(filter->predicate.get());
                auto left_attrs = get_produced_attributes(*join->left);
                auto right_attrs = get_produced_attributes(*join->right);

                std::vector<std::unique_ptr<ExpressionNode>> left_conjuncts;
                std::vector<std::unique_ptr<ExpressionNode>> right_conjuncts;
                std::vector<std::unique_ptr<ExpressionNode>> unpushed_conjuncts;

                for (auto& c : conjuncts) {
                    auto ref_cols = get_referenced_columns(*c);

                    bool can_left = !ref_cols.empty();
                    for (const auto& col : ref_cols) {
                        if (left_attrs.find(col) == left_attrs.end()) {
                            can_left = false;
                            break;
                        }
                    }

                    bool can_right = !ref_cols.empty();
                    for (const auto& col : ref_cols) {
                        if (right_attrs.find(col) == right_attrs.end()) {
                            can_right = false;
                            break;
                        }
                    }

                    if (can_left && !can_right) {
                        left_conjuncts.push_back(std::move(c));
                    } else if (can_right && !can_left) {
                        right_conjuncts.push_back(std::move(c));
                    } else {
                        unpushed_conjuncts.push_back(std::move(c));
                    }
                }

                if (!left_conjuncts.empty()) {
                    auto left_pred = combine_conjunction(std::move(left_conjuncts));
                    join->left = std::make_unique<IRFilter>(std::move(join->left), std::move(left_pred));
                    join->left = pushdown_predicates(std::move(join->left));
                }

                if (!right_conjuncts.empty()) {
                    auto right_pred = combine_conjunction(std::move(right_conjuncts));
                    join->right = std::make_unique<IRFilter>(std::move(join->right), std::move(right_pred));
                    join->right = pushdown_predicates(std::move(join->right));
                }

                if (unpushed_conjuncts.empty()) {
                    return join;
                } else {
                    auto remaining_pred = combine_conjunction(std::move(unpushed_conjuncts));
                    return std::make_unique<IRFilter>(std::move(join), std::move(remaining_pred));
                }
            }

            return node;
        }

        case IRNodeType::Project: {
            auto* p = static_cast<IRProject*>(node.get());
            if (p->child) p->child = pushdown_predicates(std::move(p->child));
            return node;
        }

        case IRNodeType::Sort: {
            auto* s = static_cast<IRSort*>(node.get());
            if (s->child) s->child = pushdown_predicates(std::move(s->child));
            return node;
        }

        case IRNodeType::Limit: {
            auto* l = static_cast<IRLimit*>(node.get());
            if (l->child) l->child = pushdown_predicates(std::move(l->child));
            return node;
        }

        case IRNodeType::HashJoin: {
            auto* j = static_cast<IRHashJoin*>(node.get());
            if (j->left) j->left = pushdown_predicates(std::move(j->left));
            if (j->right) j->right = pushdown_predicates(std::move(j->right));
            return node;
        }

        case IRNodeType::GraphTraverse: {
            auto* g = static_cast<IRGraphTraverse*>(node.get());
            if (g->child) g->child = pushdown_predicates(std::move(g->child));
            return node;
        }

        case IRNodeType::BlastRadius: {
            auto* b = static_cast<IRBlastRadius*>(node.get());
            if (b->child) b->child = pushdown_predicates(std::move(b->child));
            return node;
        }

        case IRNodeType::Aggregate: {
            auto* a = static_cast<IRAggregate*>(node.get());
            if (a->child) a->child = pushdown_predicates(std::move(a->child));
            return node;
        }
    }

    return node;
}

std::unique_ptr<IRNode> IROptimizer::optimize_node(std::unique_ptr<IRNode> node) {
    if (!node) return nullptr;

    // Pass 1: Constant folding & dead filter elimination
    node = fold_constants(std::move(node));

    // Pass 2: Predicate pushdown
    node = pushdown_predicates(std::move(node));

    // Pass 3: Post-pushdown constant folding and filter merging
    node = fold_constants(std::move(node));

    return node;
}

IRPlan IROptimizer::optimize(const IRPlan& plan) {
    IRPlan result = clone_ir_plan(plan);
    if (result.root) {
        result.root = optimize_node(std::move(result.root));
    }
    return result;
}

} // namespace sbom_dsl
