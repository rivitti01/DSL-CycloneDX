# Phase 0: CycloneDX and `sbom-utility` Analysis

This document reports the findings of the preliminary investigation conducted on the CycloneDX specifications and the official [`sbom-utility`](https://github.com/CycloneDX/sbom-utility) tool, in preparation for designing the Domain Specific Language (DSL) for the **Formal Languages and Compilers** course (Politecnico di Milano).

---

## 1. What `sbom-utility` is and what it does

`sbom-utility` is an open-source command-line application developed within the OWASP CycloneDX project (written in Go). Its objective is to validate, analyze, query, and modify Software Bill of Materials (SBOM) documents in CycloneDX and SPDX formats.

### Main commands provided by the tool:
1. **`validate`**: Validates SBOMs (CycloneDX or SPDX) against their respective official JSON schemas and any custom enterprise schemas or rules.
2. **`query`**: Executes "SQL-like" queries on the SBOM document's JSON object model using `--from`, `--select`, and `--where` flags.
3. **`component list`**: Extracts the list of declared components (`metadata.component` and the `components` array), supporting tabular output formats (`txt`, `csv`, `md`).
4. **`vulnerability list`**: Lists declared vulnerabilities (the `vulnerabilities` array in CycloneDX VEX/VDR) with CVSS severity, CWE, analysis status, and affected entities.
5. **`license list` / `license policy`**: Extracts declared licenses and evaluates compliance against policies configured in a `license.json` file.
6. **`resource list`**: Lists components and services.
7. **`trim`, `patch`, `diff`**: Document modification features (field reduction, RFC 6902 JSON patch application, SBOM delta calculation).

### How the `query` command works in `sbom-utility`:
- `--from <dot.path>`: Dereferences a dotted path in the JSON document (e.g., `metadata.component`, `components`, `vulnerabilities`, `dependencies`).
- `--select <k1,k2,...>`: Projects a list of top-level keys from the object or array elements (or `*` for all).
- `--where <k1=regex,k2=regex>`: Filters array elements by enforcing regex matches (with an implicit `AND` operation) on top-level properties.
- **Output**: The `query` command exclusively supports JSON output format.

---

## 2. How information is represented in CycloneDX

CycloneDX SBOMs (from v1.2 to v1.6+) structure software data through key sections:

1. **Root Component (`metadata.component`)**:
   Represents the main application (name, version, type `application`, `bom-ref`).
2. **Components (`components[]`)**:
   Inventory of libraries, frameworks, modules, containers, or files.
   - Each component has a unique identifier: `bom-ref` (often in Package URL format - `purl`, e.g., `pkg:npm/express@4.17.1`).
   - Contains attributes: `name`, `version`, `type` (`library`, `framework`, `application`), `description`, `licenses[]`, `hashes[]`, `supplier`, `purl`.
3. **Dependency Graph (`dependencies[]`)**:
   Represents direct dependency relationships between components:
   ```json
   "dependencies": [
     {
       "ref": "pkg:npm/my-app@1.0.0",
       "dependsOn": [
         "pkg:npm/express@4.17.1",
         "pkg:npm/lodash@4.17.21"
       ]
     },
     {
       "ref": "pkg:npm/express@4.17.1",
       "dependsOn": [
         "pkg:npm/qs@6.7.0"
       ]
     }
   ]
   ```
   If $A$ includes $B$ in `dependsOn`, $A$ directly depends on $B$. If $B$ depends on $C$, $A$ transitively depends on $C$.
4. **Vulnerabilities (`vulnerabilities[]`)**:
   Represents known CVEs or security advisories (CycloneDX 1.4+ VEX/VDR):
   - `id`: Unique identifier (e.g., `CVE-2021-44228`).
   - `ratings[]`: Severity (`critical`, `high`, `medium`, `low`) and numerical CVSS score.
   - `affects[]`: List of `{"ref": "<bom-ref>"}` objects connecting the vulnerability to affected components via their `bom-ref`.

---

## 3. Critical limitations of `sbom-utility`

Analyzing the Go source code of `sbom-utility` reveals fundamental limitations when compared to expectations for a full-fledged software security query language:

1. **Total lack of Join / Relational correlation support**:
   `sbom-utility` operates on only a single collection at a time. It cannot correlate `vulnerabilities` with `components`: for instance, it cannot answer *"Show name, version, and license of components with Critical vulnerabilities"*.
2. **No Dependency Graph analysis support**:
   No commands exist to compute:
   - Transitive dependencies (transitive closure).
   - Reverse dependencies (*"Who uses this library?"* / reverse lookup).
   - Dependency paths (*"Which chain leads the application to import library X?"*).
   Querying `--from dependencies` simply returns the static adjacency list serialized in the JSON.
3. **Extremely primitive filter predicates (`--where`)**:
   - Only accepts regex equality `field=regex`.
   - No support for `OR`, `NOT`, nested boolean expressions, or parentheses.
   - No numerical comparisons (e.g., `score >= 7.5`).
   - No navigation into nested fields (e.g., `ratings[0].severity`).
4. **Lack of advanced projections and aggregations**:
   No support for `COUNT`, `DISTINCT`, aliases (`AS`), or computed fields.
5. **Execution overhead from C++**:
   Invoking `sbom-utility` for each operation requires spawning external processes (`fork`/`exec`), parsing JSON streams from pipes, and depending on an installed Go binary on the host system.

---

## 4. Architectural Decision: Hybrid Strategy / Dual Engine

In line with the instructor's guidelines (*"for example by generating sbom-utility commands... evaluate a hybrid strategy where the DSL directly uses the CycloneDX structure"*), the ideal architectural solution comprises:

1. **`sbom-utility` Command Generator (CLI Target)**:
   - The compiler maps compatible basic queries into corresponding `sbom-utility query` and `sbom-utility component list` commands.
   - Using the `--explain` or `--target=sbom-utility` flag, the compiler displays and can invoke the tool's native commands.
2. **Native CycloneDX Engine in C++ (In-Memory Target)**:
   - A modern C++ engine based on AST/IR that directly analyzes the CycloneDX document (using `nlohmann/json`).
   - Builds fast in-memory indexes: hash map of `bom-ref`s, direct and reverse dependency graphs, `affects -> component` index.
   - Executes joins, transitive closures, shortest path algorithms, and complex predicates (`AND`, `OR`, `NOT`, numerical comparisons).
3. **Formal Query Lowering**:
   - Advanced security constructs in the DSL are lowered into core IR primitives (scans, filters, relational joins, graph closures).
   - This ensures both the theoretical rigor required by the Compilers course and maximum practical utility for software supply chain investigation.

---

## 5. Features we will use and expose in the DSL

### Features exposed by the DSL:
- **Basic SQL-like Queries**:
  - `SELECT <fields>` with support for specific fields or `*`.
  - `FROM <collection>` (`components`, `vulnerabilities`, `dependencies`, `metadata.component`).
  - `WHERE <expression>` with operators `=`, `!=`, `<`, `<=`, `>`, `>=`, `LIKE`, `MATCHES`, `CONTAINS`, combinable with `AND`, `OR`, `NOT`, and parentheses.
  - `ORDER BY <field> [ASC | DESC]`.
  - `LIMIT <n>`.
- **Advanced Domain Constructs (Security & Supply Chain)**:
  - `WHO USES "<component-name>" [TRANSITIVE | DIRECT];`
  - `FIND VULNERABLE (COMPONENTS | LIBRARIES) [SEVERITY >= <level>] [WHERE ...];`
  - `SHOW DEPENDENCY PATH FROM "<source>" TO "<target>";`
  - `SHOW TREE [OF "<component>"] [DEPTH <n>];`
  - `FIND IMPACT OF VULNERABILITY "<cve-id>";`
  - `AUDIT LICENSES [ALLOWING (...) | REJECTING (...)];`

### Excluded features and rationale:
- **Modification commands (`patch`, `trim`)**: Our project is a query and analysis language (Query Language), not a tool for mutating or patching JSON files.
- **Custom schema validation (`validate --custom`)**: Formal validation of the input SBOM can be performed upstream (or delegated directly to the tool), but does not belong to the domain of a query language.
- **Support for non-CycloneDX JSON formats**: `sbom-utility query` only supports CycloneDX JSON (rejects SPDX or XML for queries). Keeping focus on standard CycloneDX JSON (v1.2–v1.6+) ensures maximum semantic depth without diluting efforts across heterogeneous format parsers.
