# Semantic Analysis and Type System (Semantics)

This document defines the semantic rules, data model, and type system implemented during the **Semantic Analysis** phase of the CycloneDX Query DSL.

---

## 1. CycloneDX Domain Model and Symbols

The compiler incorporates a **Schema Catalog** aware of the CycloneDX specifications (v1.2 – v1.6+). Valid collections and their respective fields are formalized as follows:

### 1.1 Valid Collections
- `components`: Inventory of software components (libraries, frameworks, modules, containers).
- `vulnerabilities`: Catalog of declared vulnerabilities (CycloneDX VEX/VDR).
- `dependencies`: Dependency graph represented as adjacency lists (`ref` $\rightarrow$ `dependsOn[]`).
- `metadata.component`: Description of the primary root component or application.
- `services`: Declared services and endpoints within the architecture.

Attempting to query an unregistered collection triggers an immediate semantic error:
```
error: Unknown collection 'unknown_coll'. Valid collections are: components, vulnerabilities, dependencies, metadata.component, services
```

---

## 2. Type System

The DSL implements a static yet flexible type system to validate expressions and predicates prior to execution:

| Type | Description | Examples |
| :--- | :--- | :--- |
| `String` | Alphanumeric text | `"express"`, `'library'`, `"CVE-2021-44228"` |
| `Integer` | Whole number | `10`, `502`, `1321` |
| `Float` | Decimal floating-point number | `7.5`, `9.8`, `10.0` |
| `Boolean` | Truth value | `true`, `false` |
| `Severity` | Ordered CVSS severity level | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `NONE` |
| `Array` | List/vector of elements | `dependencies[].dependsOn`, `vulnerabilities[].cwes` |
| `Object` | Nested JSON object structure | `ratings[0]`, `supplier` |

### 2.1 Expression Type Inference Rules
1. **Literals**: The type directly matches the token value (`String`, `Integer`, `Float`, `Boolean`, `Severity`).
2. **Column References (`ColumnRefExpr`)**:
   - `ratings.severity`, `severity`, `cvss-severity` $\rightarrow$ `Severity`
   - `ratings.score`, `score` $\rightarrow$ `Float`
   - `cwe` $\rightarrow$ `Integer`
   - `name`, `version`, `type`, `bom-ref`, `purl`, `description`, `id` $\rightarrow$ `String`
3. **Unary Operators**:
   - `NOT <expr>`: requires `<expr>` to be of type `Boolean` and evaluates to `Boolean`.
4. **Binary Operators**:
   - Any comparison operator (`=`, `!=`, `<`, `<=`, `>`, `>=`, `CONTAINS`, `MATCHES`, `LIKE`) yields a result of type `Boolean`.
   - Logical operators (`AND`, `OR`) require both operands to be of type `Boolean` and yield `Boolean`.

---

## 3. Operator Compatibility Matrix

| Operator | Left Operand | Right Operand | Validity | Notes |
| :--- | :--- | :--- | :--- | :--- |
| `=`, `!=` | `T` | `T` | **Valid** | Equality for identical types |
| `=`, `!=` | `Integer` | `Float` | **Valid** | Implicit numeric promotion |
| `<`, `<=`, `>`, `>=` | `Numeric` | `Numeric` | **Valid** | Numeric order comparison |
| `<`, `<=`, `>`, `>=` | `Severity` | `Severity` | **Valid** | CVSS severity order (`NONE` < `INFO` < `LOW` < `MEDIUM` < `HIGH` < `CRITICAL`) |
| `<`, `<=`, `>`, `>=` | `String` | `Numeric` | **Semantic Error** | Type mismatch |
| `AND`, `OR` | `Boolean` | `Boolean` | **Valid** | Logical connectives |
| `AND`, `OR` | `String` | `Boolean` | **Semantic Error** | Non-boolean left operand |
| `CONTAINS` | `String` | `String` | **Valid** | Case-insensitive substring check |
| `LIKE` | `String` | `String` (Pattern) | **Valid** | SQL-style wildcard pattern matching (`%` for 0+ chars, `_` for single char) |
| `MATCHES` | `String` | `String` (Regex) | **Valid** | Regular expression matching |

---

## 4. Statement Semantic Constraints

### 4.1 `LIMIT` Clause
- The value specified in `LIMIT` must be a strictly positive integer ($> 0$). A zero or negative value raises an immediate semantic error:
  ```
  error: LIMIT must be greater than 0
  ```

### 4.2 `DEPTH` Parameter (`SHOW TREE`)
- The maximum depth value must be a positive integer ($> 0$):
  ```
  error: DEPTH must be greater than 0
  ```

### 4.3 Target for `WHO USES` and `FIND BLAST RADIUS`
- The target component identifier or CVE identifier must not be empty strings.
