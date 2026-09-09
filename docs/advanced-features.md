# Advanced Security Features and Query Lowering (30L)

This document details the **advanced security features** introduced in the CycloneDX Query DSL to fulfill the objectives of the **Formal Languages and Compilers** course (Politecnico di Milano), demonstrating a complete compilation process via **Query Lowering** to relational and graph Intermediate Representation (IR).

---

## 1. Why These Features?

In Software Supply Chain Security analysis, basic tabular queries are insufficient:
1. **Dependencies form a directed graph**: A vulnerable library is rarely imported directly by user application source code; instead, it is pulled in transitively through intermediate libraries.
2. **Data is distributed across multiple domains**: CycloneDX separates component inventory (`components`), dependency relationships (`dependencies`), and security advisories (`vulnerabilities`).
3. **`sbom-utility` supports neither relational joins nor graph analysis**: Our DSL raises the level of abstraction, enabling users to express high-level security queries that the compiler lowers into formal execution plans.

---

## 2. Detail of the 5 Advanced Constructs

---

### Construct 1: `WHO USES "<component>" [TRANSITIVE | DIRECT];`

#### Problem Solved
When a critical zero-day vulnerability is discovered in a library (e.g., `log4j-core` or `qs`), an analyst needs an immediate answer to: *"Which modules and which applications are using this library?"*.

#### Syntax and Semantics
- Syntax: `WHO USES "<component-name-or-purl>" [TRANSITIVE | DIRECT] [IN "<file.json>"];`
- Semantics: Identifies all ancestor nodes in the dependency graph with a directed path reaching the target component.

#### AST Representation
```cpp
class WhoUsesStatement : public StatementNode {
    std::string target_component;
    bool is_transitive{true};
    std::optional<std::string> bom_path;
};
```

#### IR Lowering
The Lowerer transforms the AST node into a plan comprising a scan, reverse graph traversal, and hash join:
```
Project(columns=[name, version, type, bom-ref, purl])
  └── HashJoin(on left.ref == right.bom-ref)
        ├── Left Input:
        │     GraphTraverse(target="qs", direction=REVERSE, transitive=true)
        │       └── Scan(collection="dependencies")
        └── Right Input:
              Scan(collection="components")
```

#### Example and Output
```sql
WHO USES "qs" TRANSITIVE IN "tests/fixtures/sample_cyclonedx.json";
```
Output:
```
+-------------+---------+-------------+----------------------------+----------------------------+
| name        | version | type        | bom-ref                    | purl                       |
+=============+=========+=============+============================+============================+
| body-parser | 1.19.0  | library     | pkg:npm/body-parser@1.19.0 | pkg:npm/body-parser@1.19.0 |
| express     | 4.17.1  | library     | pkg:npm/express@4.17.1     | pkg:npm/express@4.17.1     |
| my-web-app  | 2.1.0   | application | pkg:npm/my-web-app@2.1.0   | -                          |
+-------------+---------+-------------+----------------------------+----------------------------+
Total: 3 row(s) [Backend: Native CycloneDX Engine]
```

---

### Construct 2: `FIND VULNERABLE LIBRARIES [SEVERITY >= <level>];`

#### Problem Solved
`sbom-utility` lists vulnerabilities or components in isolation. `FIND VULNERABLE` executes a relational join between the vulnerability catalog and software component metadata, allowing filtering by minimum severity and component type.

#### Syntax and Semantics
- Syntax: `FIND VULNERABLE (COMPONENTS | LIBRARIES) [SEVERITY [op] <level>] [WHERE <cond>];`
- Semantics: Executes a relational equi-join between `vulnerabilities[].affects[].ref` and `components[].bom-ref`.

#### AST Representation
```cpp
class FindVulnerableStatement : public StatementNode {
    bool libraries_only{false};
    std::optional<BinaryOperator> severity_op;
    std::optional<SeverityLevel> severity_level;
    std::unique_ptr<ExpressionNode> where_clause;
    std::optional<std::string> bom_path;
};
```

#### IR Lowering
```
Project(columns=[name, version, type, vuln_id, severity, score, description])
  └── HashJoin(on left.affects == right.bom-ref)
        ├── Left Input:
        │     Filter(predicate=[ratings.severity >= HIGH])
        │       └── Scan(collection="vulnerabilities")
        └── Right Input:
              Filter(predicate=[type = "library"])
                └── Scan(collection="components")
```

#### Example and Output
```sql
FIND VULNERABLE LIBRARIES SEVERITY >= HIGH IN "tests/fixtures/sample_cyclonedx.json";
```
Output:
```
+------------+---------+---------+----------------+----------+-------+----------------------+
| name       | version | type    | vuln_id        | severity | score | description          |
+============+=========+=========+================+==========+=======+======================+
| log4j-core | 2.14.1  | library | CVE-2021-44228 | critical | 10.0  | Apache Log4j Core    |
| qs         | 6.7.0   | library | CVE-2022-29244 | high     | 7.5   | A querystring parser |
+------------+---------+---------+----------------+----------+-------+----------------------+
Total: 2 row(s) [Backend: Native CycloneDX Engine]
```

---

### Construct 3: `SHOW TREE [OF "<root>"] [DEPTH <n>];`

#### Problem Solved
Provides a visual representation of the dependency tree structure to understand the exact paths through which libraries are pulled in.

#### Syntax and Semantics
- Syntax: `SHOW (TREE | DEPENDENCIES) [OF "<component>"] [DEPTH <n>] [IN "<file.json>"];`
- Semantics: Executes a BFS/DFS in the outgoing (`FORWARD`) direction starting from the specified root node up to the requested maximum depth.

#### IR Lowering
```
Project(columns=[name, version, depth, bom-ref])
  └── HashJoin(on left.ref == right.bom-ref)
        ├── Left Input:
        │     GraphTraverse(target="my-web-app", direction=FORWARD, max_depth=2)
        │       └── Scan(collection="dependencies")
        └── Right Input:
              Scan(collection="components")
```

#### Example with Hierarchical Tree Output (`--format tree`)
```sql
SHOW TREE OF "my-web-app" DEPTH 2;
```
Output:
```
Dependency Tree:
└── express@4.17.1
└── log4j-core@2.14.1
│   └── body-parser@1.19.0
```

---

### Construct 4: `FIND BLAST RADIUS OF "<cve-id>";`

#### Problem Solved
Evaluates the global impact of a CVE across the system: computes what fraction of the entire software base is compromised and determines whether the primary root application (`metadata.component`) or external services are reachable and exposed.

#### Syntax and Semantics
- Syntax: `FIND BLAST RADIUS OF "<cve-id>" [IN "<file.json>"];`
- Semantics: Identifies components affected by the vulnerability, computes reverse reachability (transitive closure in reverse), calculates impacted node cardinality, and verifies intersection with the root application node.

#### IR Lowering
```
BlastRadius(vulnerability_id="CVE-2021-44228")
  └── Scan(collection="vulnerabilities")
```

#### Example and Output
```sql
FIND BLAST RADIUS OF "CVE-2021-44228" IN "tests/fixtures/sample_cyclonedx.json";
```
Output:
```
+----------------------------------+-----------------------+
| Metric                           | Value                 |
+==================================+=======================+
| Vulnerability ID                 | CVE-2021-44228        |
| CVSS Severity                    | critical              |
| CVSS Score                       | 10.000000             |
| Total Components in SBOM         | 6                     |
| Directly Affected Components     | 1                     |
| Transitively Impacted Components | 2                     |
| Blast Radius (%)                 | 33.333333%            |
| Root Application Exposed?        | YES (CRITICAL IMPACT) |
+----------------------------------+-----------------------+
```

---

---

### Construct 5: `ASSERT NO <target> [SEVERITY ...] [WHERE ...];` (Policy Enforcement & CI/CD Gatekeeping)

#### Problem Solved
Security analysts and DevSecOps pipelines require automated gatekeeping mechanisms to prevent deploying software violating compliance rules (e.g. presence of critical vulnerabilities, forbidden licensing, or blacklisted modules).

#### Syntax and Semantics
- Syntax: `ASSERT NO (VULNERABILITIES | COMPONENTS | LIBRARIES) [SEVERITY [op] <level_or_score>] [WHERE <cond>] [IN "<file.json>"];`
- Semantics: Scans the target collection (with relational join against components if severity is filtered), evaluates compliance predicates. If any violating records match, the query reports all offending records and terminates with exit code `1` (or non-zero in CI/CD). If zero records violate the policy, execution succeeds with exit code `0` (`POLICY PASSED`).

#### AST Representation
```cpp
class AssertStatement : public StatementNode {
    AssertTarget target; // Vulnerabilities, Components, Libraries
    std::optional<BinaryOperator> severity_op;
    std::optional<SeverityLevel> severity_level;
    std::optional<double> cvss_threshold;
    std::unique_ptr<ExpressionNode> where_clause;
    std::optional<std::string> bom_path;
};
```

#### IR Lowering
```
Project(columns=[name, version, type, vuln_id, severity, score])
  └── HashJoin(on left.affects == right.bom-ref)
        ├── Left Input:
        │     Filter(predicate=[ratings.severity >= HIGH])
        │       └── Scan(collection="vulnerabilities")
        └── Right Input:
              Scan(collection="components")
```

#### Example and Output
```sql
ASSERT NO VULNERABILITIES SEVERITY >= HIGH IN "tests/fixtures/sample_cyclonedx.json";
```
Output:
```
[POLICY VIOLATION] Assert condition failed: offending records detected!
+------------+---------+---------+----------------+----------+-------+
| name       | version | type    | vuln_id        | severity | score |
+============+=========+=========+================+==========+=======+
| log4j-core | 2.14.1  | library | CVE-2021-44228 | critical | 10.0  |
| qs         | 6.7.0   | library | CVE-2022-29244 | high     | 7.5   |
+------------+---------+---------+----------------+----------+-------+
Total: 2 offending record(s) found.
Policy Gatekeeping: FAILED (Exit Code 1)
```

---

### Construct 6: Multi-Stage Compiler with `--explain` Mode, IR Optimizer, and Dual Backend

#### Academic Value
During project presentation, it is essential to demonstrate that the system is a **genuine multi-stage compiler** rather than a simple script.

The `--explain` flag isolates and renders:
1. **Lexical Phase (`[PHASE 1]`)**: Formal token listing with positional coordinates (`line:column`);
2. **Syntactic Phase (`[PHASE 2]`)**: Hierarchical AST structure;
3. **Semantic Phase (`[PHASE 3]`)**: Validation outcome against the CycloneDX schema catalog;
4. **Lowering Phase (`[PHASE 4]`)**: Relational and graph IR execution plan;
5. **Algebraic Optimizer (`[PHASE 4.1]`)**: Rule-based IR optimization pass (Constant Folding, Filter Fusion, Predicate Pushdown across joins);
6. **Code Generation Phase (`[PHASE 5]`)**: Automatic translation into the `sbom-utility query ...` CLI command for supported queries, or analytical explanation of why the query requires the native in-memory engine (due to relational joins, graph traversals, or aggregations);
7. **Formatted Execution Results**: Output delivered in ASCII table, JSON, hierarchical Tree, Graphviz DOT (`--format dot`), or Mermaid diagram (`--format mermaid`).

