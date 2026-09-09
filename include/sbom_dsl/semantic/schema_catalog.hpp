#pragma once

#include <string>
#include <string_view>
#include <unordered_set>
#include <unordered_map>

namespace sbom_dsl {

enum class DataType {
    String,
    Integer,
    Float,
    Boolean,
    Severity,
    Array,
    Object,
    Unknown
};

std::string_view data_type_name(DataType type);

class SchemaCatalog {
public:
    static SchemaCatalog& instance();

    bool is_valid_collection(std::string_view collection) const;
    bool is_valid_field(std::string_view collection, std::string_view field) const;
    DataType get_field_type(std::string_view collection, std::string_view field) const;

private:
    SchemaCatalog();

    std::unordered_set<std::string> collections_;
    std::unordered_map<std::string, std::unordered_map<std::string, DataType>> schema_fields_;
};

} // namespace sbom_dsl
