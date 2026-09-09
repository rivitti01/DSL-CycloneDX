#include "sbom_dsl/semantic/schema_catalog.hpp"

namespace sbom_dsl {

std::string_view data_type_name(DataType type) {
    switch (type) {
        case DataType::String: return "String";
        case DataType::Integer: return "Integer";
        case DataType::Float: return "Float";
        case DataType::Boolean: return "Boolean";
        case DataType::Severity: return "Severity";
        case DataType::Array: return "Array";
        case DataType::Object: return "Object";
        case DataType::Unknown: return "Unknown";
    }
    return "Unknown";
}

SchemaCatalog& SchemaCatalog::instance() {
    static SchemaCatalog catalog;
    return catalog;
}

SchemaCatalog::SchemaCatalog() {
    collections_ = {
        "components",
        "vulnerabilities",
        "dependencies",
        "metadata.component",
        "services"
    };

    // components fields
    schema_fields_["components"] = {
        {"name", DataType::String},
        {"version", DataType::String},
        {"type", DataType::String},
        {"bom-ref", DataType::String},
        {"purl", DataType::String},
        {"description", DataType::String},
        {"scope", DataType::String},
        {"licenses", DataType::Array},
        {"hashes", DataType::Array},
        {"supplier", DataType::Object},
        {"author", DataType::String}
    };

    // vulnerabilities fields
    schema_fields_["vulnerabilities"] = {
        {"id", DataType::String},
        {"source", DataType::Object},
        {"ratings", DataType::Array},
        {"ratings.severity", DataType::Severity},
        {"ratings.score", DataType::Float},
        {"severity", DataType::Severity},
        {"score", DataType::Float},
        {"cvss-severity", DataType::Severity},
        {"cwe", DataType::Integer},
        {"cwes", DataType::Array},
        {"description", DataType::String},
        {"detail", DataType::String},
        {"recommendation", DataType::String},
        {"affects", DataType::Array},
        {"analysis", DataType::Object}
    };

    // dependencies fields
    schema_fields_["dependencies"] = {
        {"ref", DataType::String},
        {"dependsOn", DataType::Array}
    };

    // metadata.component fields
    schema_fields_["metadata.component"] = {
        {"name", DataType::String},
        {"version", DataType::String},
        {"type", DataType::String},
        {"bom-ref", DataType::String},
        {"purl", DataType::String},
        {"description", DataType::String}
    };

    // services fields
    schema_fields_["services"] = {
        {"name", DataType::String},
        {"version", DataType::String},
        {"bom-ref", DataType::String},
        {"endpoints", DataType::Array},
        {"authenticated", DataType::Boolean}
    };
}

bool SchemaCatalog::is_valid_collection(std::string_view collection) const {
    return collections_.find(std::string(collection)) != collections_.end();
}

bool SchemaCatalog::is_valid_field(std::string_view collection, std::string_view field) const {
    auto col_it = schema_fields_.find(std::string(collection));
    if (col_it == schema_fields_.end()) return false;
    return col_it->second.find(std::string(field)) != col_it->second.end();
}

DataType SchemaCatalog::get_field_type(std::string_view collection, std::string_view field) const {
    auto col_it = schema_fields_.find(std::string(collection));
    if (col_it == schema_fields_.end()) return DataType::Unknown;
    auto field_it = col_it->second.find(std::string(field));
    if (field_it == col_it->second.end()) return DataType::Unknown;
    return field_it->second;
}

} // namespace sbom_dsl
