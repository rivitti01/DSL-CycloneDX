# Language Reference Manual (DSL Reference)

The **CycloneDX Query DSL** is a domain-oriented language designed to enable developers, security analysts, and supply chain managers to query, filter, and analyze Software Bill of Materials (SBOM) documents conforming to the CycloneDX standard.

---

## 1. General Query Structure

Each statement terminates with a semicolon `;`. Multiple statements can be written sequentially in the same script or interactive session.

Comments are supported using SQL or C/C++ style syntax:
```sql
-- Single-line SQL-style comment
// Single-line C++-style comment
/* Multi-line
   comment */
```

The target SBOM file can be specified in three ways:
1. Inside the query using the `IN "path/to/file.json"` clause;
2. Via the command-line flag `-b path/to/file.json`;
3. Within an interactive REPL session using `:bom path/to/file.json`.

---

## 2. Basic SQL-like Queries (`SELECT`)

### 2.1 Syntax
```sql
SELECT <projections>
FROM <collection>
[IN "<sbom_file.json>"]
[WHERE <condition>]
[ORDER BY <field> [ASC | DESC]]
[LIMIT <number>];
```

### 2.2 Supported Collections (`FROM`)
- `components`: Inventory of software components (libraries, frameworks, modules).
- `vulnerabilities`: Catalog of declared vulnerabilities (CycloneDX VEX/VDR).
- `dependencies`: Direct dependency graph (`ref` and `dependsOn`).
- `metadata.component`: Information regarding the primary application or root system.

### 2.3 Projections
- `SELECT *` selects all available fields.
- `SELECT field1, field2, ...` selects only the specified fields (e.g., `name, version, type, purl`).

### 2.4 Filter Conditions (`WHERE`)
Supports comprehensive logical and relational expressions:
- **Equality and inequality**: `=`, `!=`
- **Numerical comparisons / ordering**: `<`, `<=`, `>`, `>=`
- **Logical operators**: `AND`, `OR`, `NOT`, with parentheses `( ... )`
- **String operators**:
  - `LIKE`: SQL-style wildcard pattern matching using `%` (matches zero or more characters) and `_` (matches a single character). Case-insensitive (e.g., `name LIKE 'log%'` or `name LIKE '%parser'`).
  - `CONTAINS`: case-insensitive substring search (e.g., `purl CONTAINS 'npm'` or `name CONTAINS 'log4j'`).
  - `MATCHES`: regular expression matching (e.g., `description MATCHES 'JNDI.*LDAP'`).

### 2.5 Examples
```sql
-- All libraries ordered by name
SELECT name, version, purl
FROM components
WHERE type = 'library'
ORDER BY name ASC
LIMIT 10;

-- Pattern matching on library names and purl
SELECT name, version
FROM components
WHERE name LIKE 'exp%' AND purl CONTAINS 'npm';

-- Vulnerabilities with high CVSS score
SELECT id, cvss-severity, score
FROM vulnerabilities
WHERE score >= 7.5 AND (severity = CRITICAL OR severity = HIGH);
```

---

## 3. Advanced Security Constructs

### 3.1 `WHO USES` (Reverse Dependency Lookup)
Answers the critical supply chain question: *"Which components in my project are using this specific library?"*.

```sql
WHO USES "<component-identifier>" [TRANSITIVE | DIRECT] [IN "<file.json>"];
```
- When omitted, the default behavior is `TRANSITIVE` (explores the entire dependency chain up to the root).
- If `DIRECT` is specified, only components that declare an immediate direct dependency are returned.

**Example:**
```sql
WHO USES "log4j-core" TRANSITIVE;
```

---

### 3.2 `FIND VULNERABLE` (Vulnerability-Component Correlation)
Performs an automatic relational join between the vulnerability catalog and components, correlating component metadata with security advisories.

```sql
FIND VULNERABLE (COMPONENTS | LIBRARIES)
[SEVERITY [= | != | < | <= | > | >=] <level>]
[WHERE <additional_condition>]
[IN "<file.json>"];
```
- `COMPONENTS`: analyzes all components (applications, containers, libraries, modules).
- `LIBRARIES`: restricts the analysis strictly to third-party libraries.
- `SEVERITY`: filters by CVSS severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `NONE`).

**Examples:**
```sql
-- Find libraries with high or critical severity vulnerabilities
FIND VULNERABLE LIBRARIES SEVERITY >= HIGH;

-- Find vulnerable components with a specific CWE
FIND VULNERABLE COMPONENTS WHERE cwe = 502;
```

---

### 3.3 `SHOW TREE` (Dependency Tree Visualization)
Reconstructs the hierarchical structure of direct and transitive dependencies.

```sql
SHOW (TREE | DEPENDENCIES) [OF "<component-name>"] [DEPTH <n>] [IN "<file.json>"];
```
- `OF "<component>"`: selects the root node of the tree (if omitted, defaults to the application defined in `metadata.component`).
- `DEPTH <n>`: bounds the maximum depth of the displayed dependency tree.

**Example:**
```sql
SHOW TREE OF "my-web-app" DEPTH 3;
```

---

### 3.4 `FIND BLAST RADIUS` (Impact Analysis)
Computes the global blast radius and exposure of the system relative to a known vulnerability (CVE).

```sql
FIND BLAST RADIUS OF "<cve-id>" [IN "<file.json>"];
```
Returns a summary report containing:
- CVSS Score and advisory severity;
- Directly affected components;
- Transitively impacted components;
- Supply chain compromise percentage (`Blast Radius %`);
- Assessment of whether the top-level root application is directly or transitively exposed.

**Example:**
```sql
FIND BLAST RADIUS OF "CVE-2021-44228";
```

---

### 3.5 `ASSERT NO` (Policy Enforcement & CI/CD Gatekeeping)
Enforces security and compliance policies directly within DevSecOps Continuous Integration pipelines (e.g., GitHub Actions, GitLab CI).

```sql
ASSERT NO <target>
[SEVERITY [op] <level_or_score>]
[WHERE <condition>]
[IN "<file.json>"];
```

#### Targets (`<target>`)
- `VULNERABILITIES`: Checks for policy-violating vulnerabilities impacting components in the SBOM.
- `COMPONENTS`: Checks for prohibited software components (e.g., specific framework, unwanted supplier).
- `LIBRARIES`: Checks for prohibited third-party libraries.

#### Severity and Score Thresholds
- **Severity Level**: `SEVERITY >= HIGH`, `SEVERITY = CRITICAL`
- **CVSS Score**: `SEVERITY > 10.0`, `SEVERITY >= 7.5`

#### CI/CD Exit Code Protocol
- **Exit Code `0` (Success/Compliant)**: When no matching violating records are found. Stampa un banner di conformità.
- **Exit Code `1` (Failure/Non-Compliant)**: When one or more policy violations are detected. Stampa la tabella dettagliata dei componenti e vulnerabilità incriminati e termina con codice di uscita 1.

**Examples:**
```sql
-- Block pipeline if any critical or high vulnerability is found
ASSERT NO VULNERABILITIES SEVERITY >= HIGH;

-- Block pipeline if any vulnerability has CVSS score >= 9.0
ASSERT NO VULNERABILITIES SEVERITY >= 9.0;

-- Disallow framework components
ASSERT NO COMPONENTS WHERE type = 'framework';

-- Block deprecated or unwanted libraries
ASSERT NO LIBRARIES WHERE name = 'log4j-core' AND version LIKE '2.14%';
```


## 4. Execution Modes and Formatting

### 4.1 Output Formats (`-f`, `--format`)
1. **ASCII Table (`table`)**: Default format with aligned columns, row count statistics, and execution time.
2. **JSON (`json`)**: Standard JSON output suitable for CI/CD pipelines or scripting integration.
3. **Tree (`tree`)**: Hierarchical tree visualization using box-drawing characters (`├──`, `└──`), ideal for `SHOW TREE`.
4. **Graphviz DOT (`dot`)**: Directed graph format (`digraph { ... }`) for rendering diagrams via Graphviz tools (`dot -Tpng`, `dot -Tsvg`). Includes semantic security coloring (root in blue, target vulnerabilities in red, transitive impacts in orange).
5. **Mermaid (`mermaid`)**: Diagram specification (`graph TD`) for instant rendering in Markdown files, GitHub, and documentation viewers. Includes automated styling and semantic vulnerability impact highlights.

### 4.2 Explain Mode (`--explain`)
Adding `--explain` to the command line (or `:explain on` in the REPL) outputs a detailed breakdown of each compilation phase:
1. Lexer-generated tokens with `line:column` coordinates;
2. Abstract Syntax Tree (`AST`);
3. Semantic analysis and type validation report;
4. Lowered execution plan (`IR Execution Plan`);
5. Mapping and synthesized `sbom-utility` command (if applicable).
