# CycloneDX Query DSL (Domain Specific Language)

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.wikipedia.org/wiki/C%2B%2B20)
[![CMake](https://img.shields.io/badge/CMake-3.20+-darkcyan.svg)](https://cmake.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-Passing%20(100%25)-brightgreen.svg)]()

> Project for the **Formal Languages and Compilers** course — Politecnico di Milano.  
> Objective: Design and implementation of a complete compiler for a Domain Specific Language (DSL) targeting querying and security analysis of Software Bill of Materials (SBOM) in **CycloneDX** format.

---

## Table of Contents
- [Project Overview](#project-overview)
- [Compiler Architecture](#compiler-architecture)
- [Language Features](#language-features)
  - [1. Basic SQL-like Queries and Aggregations](#1-basic-sql-like-queries-and-aggregations)
  - [2. Advanced Security Constructs](#2-advanced-security-constructs)
  - [3. Comments and SBOM Specification](#3-comments-and-sbom-specification)
- [Requirements and Build](#requirements-and-build)
- [Running Tests](#running-tests)
- [CLI Guide](#cli-guide)
  - [Command-Line Options Reference](#command-line-options-reference)
  - [DevSecOps & CI/CD Exit Codes](#devsecops--cicd-exit-codes)
  - [Output Formats](#output-formats)
  - [Explain Mode (`--explain`)](#explain-mode---explain)
  - [Interactive Shell (REPL)](#interactive-shell-repl)
- [Complete Documentation](#complete-documentation)
- [Limitations and Future Work](#limitations-and-future-work)

---

## Project Overview

A Software Bill of Materials (SBOM) is the formal inventory of all software components, dependencies, and known vulnerabilities of an application. The **CycloneDX** format (OWASP) is one of the leading industry standards.

This project implements a modular C++20 compiler and interpreter featuring:
1. **A SQL-like query language** to selectively query CycloneDX collections (`components`, `vulnerabilities`, `dependencies`, `metadata.component`).
2. **High-level software security semantic constructs** (`WHO USES`, `FIND VULNERABLE`, `SHOW TREE`, `FIND BLAST RADIUS`, `ASSERT NO`).
3. **Formal Query Lowering**: High-level constructs are compiled into an algebraic **Intermediate Representation (IR)** execution plan consisting of relational and graph primitives.
4. **Dual Execution Backend**:
   - **`sbom-utility` Code Generator**: Generates and emits CLI commands for the official OWASP [`sbom-utility`](https://github.com/CycloneDX/sbom-utility) tool;
   - **Native CycloneDX Engine**: In-memory C++ engine with hash indexes and graph algorithms (BFS, paths, transitive closures) that overcomes the limitations of the Go tool (which supports neither joins nor graphs).

---

## Compiler Architecture

The compilation pipeline strictly follows classical compiler engineering phases:

```
[ DSL Source ]
      ↓
[ Lexer ]                  → Lexical scanning with line/column tracking (SourceLocation)
      ↓
[ Parser ]                 → Recursive Descent (Statements) + Pratt Parser (Expression Precedence)
      ↓
[ AST ]                    → C++20 Abstract Syntax Tree with Visitor Pattern
      ↓
[ Semantic Analysis ]      → Type Checking & CycloneDX Schema Catalog (v1.2 - v1.6+)
      ↓
[ Query Lowerer ]          → AST lowering to relational/graph IR plan
      ↓
[ Intermediate Rep (IR) ]  → Scan, Filter, Project, Sort, Limit, HashJoin, GraphTraverse, BlastRadius, Aggregate
      ↓
[ IR Optimizer ]           → Predicate Pushdown, Filter Fusion, Projection Pushdown, Constant Folding, Dead Plan Elimination
      ↓
  +---+---------------------------+
  |                               |
  v                               v
[ sbom-utility CodeGen ]      [ Native CycloneDX Engine ]
(CLI command generation)       (In-memory execution with graphs & hash indexes)
  |                               |
  +---------------+---------------+
                  ↓
          [ Query Results ]   (ASCII Table, JSON, Hierarchical Tree, Graphviz DOT, Mermaid)
```

For more details, consult [docs/architecture.md](docs/architecture.md).

---

## Language Features

### 1. Basic SQL-like Queries and Aggregations
Allows projecting, filtering, aggregating (`COUNT(*)`, `COUNT(col)`), and grouping (`GROUP BY`) components, vulnerabilities, and dependencies using comparison, logical, and string pattern matching operators:
- **Collections (`FROM`)**: `components`, `vulnerabilities`, `dependencies`, `metadata.component`
- **Projections (`SELECT`)**: `*`, explicit column list (`name, version, purl`), scalar & grouped counts (`COUNT(*)`, `COUNT(col)`)
- **Comparison Operators**: `=`, `!=`, `<`, `<=`, `>`, `>=`
- **Logical Operators**: `AND`, `OR`, `NOT`, with arbitrary parenthesized grouping `( ... )`
- **String Pattern Operators**:
  - `LIKE`: SQL-style wildcards (`%` for zero or more characters, `_` for a single character)
  - `CONTAINS`: case-insensitive substring search
  - `MATCHES`: ECMAScript / POSIX regular expression matching (e.g. `purl MATCHES 'pkg:(npm|maven)/.*'`)
- **Ordering & Pagination**: `ORDER BY <column> [ASC | DESC]`, `LIMIT <number>`

```sql
SELECT name, version, purl
FROM components
IN "bom.json"
WHERE type = 'library' AND (name LIKE 'exp%' OR purl CONTAINS 'lodash')
ORDER BY name ASC
LIMIT 10;

-- Aggregations & Grouping
SELECT severity, COUNT(*)
FROM vulnerabilities
GROUP BY severity
ORDER BY severity ASC;
```

### 2. Advanced Security Constructs

| Construct | Security Problem Solved | Lowered IR Plan |
| :--- | :--- | :--- |
| `WHO USES "lib" [TRANSITIVE \| DIRECT];` | Identifies all direct or transitive upstream consumers up to the root application. | `Project -> HashJoin -> GraphTraverse(Reverse) -> Scan(dependencies)` |
| `FIND VULNERABLE (COMPONENTS \| LIBRARIES) [SEVERITY op level] [WHERE condition];` | Correlates component catalog with vulnerability advisories (VEX/VDR) through relational join. | `Project -> HashJoin(affects == bom-ref) -> Filter(vulns) / Filter(comps)` |
| `SHOW (TREE \| DEPENDENCIES) [OF "app"] [DEPTH n];` | Reconstructs hierarchical dependency tree in ASCII, JSON, Graphviz DOT, or Mermaid. | `Project -> HashJoin -> GraphTraverse(Forward, depth=n) -> Scan(dependencies)` |
| `FIND BLAST RADIUS OF "CVE-...";` | Computes supply chain exposure percentage, direct & transitive impact, and root app exposure. | `BlastRadius -> ReverseReachability -> Scan(vulnerabilities)` |
| `ASSERT NO (VULNERABILITIES \| COMPONENTS \| LIBRARIES) [SEVERITY op level_or_score] [WHERE condition];` | Automated CI/CD gatekeeping: returns exit code `0` on compliance or `1` with violating records. | `Project -> HashJoin -> Filter(vulns) -> Scan(components)` |

**Examples:**
```sql
-- 1. Upstream impact of an affected library
WHO USES "qs" TRANSITIVE;

-- 2. Vulnerability-component correlation
FIND VULNERABLE LIBRARIES SEVERITY >= HIGH;
FIND VULNERABLE COMPONENTS WHERE cwe = 502;

-- 3. Dependency hierarchy
SHOW TREE OF "my-web-app" DEPTH 2;

-- 4. Vulnerability blast radius
FIND BLAST RADIUS OF "CVE-2021-44228";

-- 5. DevSecOps policy enforcement
ASSERT NO VULNERABILITIES SEVERITY >= HIGH;
ASSERT NO VULNERABILITIES SEVERITY >= 9.0;
ASSERT NO COMPONENTS WHERE type = 'framework';
ASSERT NO LIBRARIES WHERE name = 'log4j-core' AND version LIKE '2.14%';
```

### 3. Comments and SBOM Specification

**Comments Syntax:**
```sql
-- SQL-style single-line comment
// C/C++ style single-line comment
/* Multi-line
   block comment */
```

**Target SBOM Specification:**
The SBOM file path can be provided through three interchangeable mechanisms:
1. Inside the query via `IN "path/to/bom.json"`;
2. Via CLI argument `-b path/to/bom.json` or `--bom path/to/bom.json`;
3. Within the interactive REPL via `:bom path/to/bom.json`.

For more details, consult [docs/advanced-features.md](docs/advanced-features.md) and [docs/language.md](docs/language.md).

---

## Requirements and Build

### Requirements
- Modern C++ compiler with full **C++20** support (AppleClang 15+, GCC 11+, Clang 13+);
- **CMake 3.20+**;
- Internet connection for the initial automatic fetch of header-only dependencies (`nlohmann/json` and `doctest` via `FetchContent`).

### Build Instructions
```bash
# 1. Clone repository
git clone https://github.com/rivitti01/DSL-CycloneDX.git
cd DSL-CycloneDX

# 2. Configure CMake
cmake -B build -DCMAKE_BUILD_TYPE=Release

# 3. Build library, CLI, and test suite
cmake --build build -j4
```
The main generated executable is `build/sbom-dsl`.

---

## Running Tests

The automated test suite covers each phase of the compiler with 100% test pass rate:
- `test_lexer`: token scanning, comment handling, escape strings, lexical error diagnostics.
- `test_parser`: recursive descent parsing, Pratt precedence climbing for complex expressions, syntax errors.
- `test_semantic`: schema catalog validation, type checking for comparators and heterogeneous types.
- `test_lowering`: accurate generation of relational and graph algebraic IR plans.
- `test_backend`: execution on real CycloneDX SBOMs, reverse lookups, relational joins, blast radius computation.
- `test_e2e`: comprehensive end-to-end tests from DSL source to formatted output.

To run all tests via CTest:
```bash
ctest --test-dir build --output-on-failure
```

---

## CLI Guide

### Command-Line Options Reference

| Option | Description |
| :--- | :--- |
| `-c <query>` | Execute query directly inline from the command line |
| `-b, --bom <file>` | Specify default CycloneDX SBOM JSON file |
| `-f, --format <format>` | Output format: `table` (default), `json`, `tree`, `dot`, `mermaid` |
| `-e, --explain` | Print comprehensive compiler phase trace (Tokens, AST, Semantic, IR, Optimizer, Codegen) |
| `-i, --interactive` | Start interactive query shell (REPL) |
| `--sbom-utility` | Attempt query execution offloading to official OWASP `sbom-utility` CLI if installed |
| `-h, --help` | Display command-line options and usage examples |
| `-v, --version` | Display version information |

### DevSecOps & CI/CD Exit Codes

The CLI implements the standard UNIX exit code convention for CI/CD pipelines:
- **Exit Code `0` (Success / Compliant)**: Query executed successfully; all `ASSERT NO` policy assertions passed (no violating components or vulnerabilities found).
- **Exit Code `1` (Failure / Policy Violation)**: One or more `ASSERT NO` policy assertions failed, or a lexical/syntax/semantic error occurred.

Example GitHub Actions / GitLab CI pipeline gate:
```bash
# CI/CD pipeline step: fails the build if any HIGH or CRITICAL vulnerability is present
./build/sbom-dsl -b bom.json -c "ASSERT NO VULNERABILITIES SEVERITY >= HIGH;"
```

### Execution Examples

```bash
# 1. Inline SQL-like query
./build/sbom-dsl -c "SELECT name, version, purl FROM components WHERE type = 'library';" -b tests/fixtures/sample_cyclonedx.json

# 2. Reverse dependency inspection
./build/sbom-dsl examples/who_uses.dsl

# 3. Relational vulnerability join
./build/sbom-dsl examples/find_vulnerable.dsl

# 4. Supply chain blast radius analysis
./build/sbom-dsl examples/blast_radius.dsl

# 5. Dependency tree inspection
./build/sbom-dsl examples/show_tree.dsl --format tree
```

### Output Formats

- **Table (`--format table`)**: Aligned ASCII table with headers, row count, execution backend, and execution time.
- **JSON (`--format json`)**: Standard structured JSON array of objects, ready for piping to `jq` or external APIs.
- **Tree (`--format tree`)**: Hierarchical tree with Unicode box-drawing characters (`└──`, `├──`), ideal for `SHOW TREE`.
- **Graphviz DOT (`--format dot`)**: Directed graph script (`digraph { ... }`) with security-themed node coloring:
  ```bash
  ./build/sbom-dsl examples/show_tree.dsl --format dot | dot -Tsvg -o dependency_tree.svg
  ```
- **Mermaid (`--format mermaid`)**: Markdown-ready `graph TD` diagrams with automated vulnerability and root node styling, renderable directly in GitHub markdown and documentation viewers.

### Explain Mode (`--explain`)
Ideal for demonstration, teaching, and academic evaluation of the compiler:
```bash
./build/sbom-dsl examples/basic_select.dsl --explain
```
Displays all intermediate representations across compilation phases:
1. `[PHASE 1] LEXICAL ANALYSIS`: Tokens generated by the Lexer with `line:column` source coordinates;
2. `[PHASE 2] ABSTRACT SYNTAX TREE (AST)`: Full AST tree hierarchy with statements and expressions;
3. `[PHASE 3] SEMANTIC ANALYSIS & TYPE CHECKING`: CycloneDX schema catalog validation;
4. `[PHASE 4] LOWERING TO IR`: Initial unoptimized relational and graph IR execution plan;
5. `[PHASE 4.1] IR OPTIMIZATION`: Algebraic optimizer pass (constant folding, predicate pushdown, filter fusion);
6. `[PHASE 5] TARGET CODEGEN (sbom-utility)`: Mappability evaluation and emitted `sbom-utility` command or Native Engine fallback rationale;
7. `[EXECUTION RESULTS]`: Query output.

### Interactive Shell (REPL)
Can be launched without arguments or with `-i`:
```bash
./build/sbom-dsl -i
```
```text
CycloneDX Query DSL Interactive Shell (REPL)
Type your queries followed by ';' or 'exit'/'quit' to exit.
Commands: ':explain [on|off]', ':bom <file>', ':format [table|json|tree|dot|mermaid]'

sbom-dsl> :bom tests/fixtures/sample_cyclonedx.json
Default SBOM set to: tests/fixtures/sample_cyclonedx.json

sbom-dsl> WHO USES 'qs' TRANSITIVE;
+-------------+---------+-------------+----------------------------+
| name        | version | type        | bom-ref                    |
+=============+=========+=============+============================+
| body-parser | 1.19.0  | library     | pkg:npm/body-parser@1.19.0 |
| express     | 4.17.1  | library     | pkg:npm/express@4.17.1     |
| my-web-app  | 2.1.0   | application | pkg:npm/my-web-app@2.1.0   |
+-------------+---------+-------------+----------------------------+
Total: 3 row(s) [Backend: Native CycloneDX Engine, Time: 0.22 ms]

sbom-dsl> :explain on
Explain mode: ON
```

---

## Complete Documentation

The [`docs/`](docs/) directory contains comprehensive monographic documentation:
- [docs/sbom_utility_analysis.md](docs/sbom_utility_analysis.md): Preliminary study of CycloneDX schema and `sbom-utility` capabilities and limitations (Phase 0).
- [docs/architecture.md](docs/architecture.md): Compiler architecture, pipeline details, and computational complexity.
- [docs/grammar.md](docs/grammar.md): Complete EBNF formal grammar, tokens, and operator precedence hierarchy.
- [docs/language.md](docs/language.md): User reference manual covering all supported statements and clauses.
- [docs/semantics.md](docs/semantics.md): Data model, CycloneDX catalog, and type system inference rules.
- [docs/advanced-features.md](docs/advanced-features.md): Theoretical details of advanced security constructs, graph algorithms, and lowering logic.
- [docs/examples.md](docs/examples.md): Extensive test cases, queries, output snippets, and `--explain` walkthroughs.

---

## Limitations and Future Work

### Completed Enhancements
- **Query Optimizer**: Rule-based algebraic IR optimization pass implementing Constant Folding, Filter Fusion, Predicate Pushdown (across Joins and Projections), Projection Pruning, and Dead Plan Elimination (`IROptimizer`).
- **Graph Export**: Support for exporting `SHOW TREE` and `FIND BLAST RADIUS` hierarchy directly into Graphviz DOT format (`--format dot`) and Mermaid markdown diagrams (`--format mermaid`), easily convertible into SVG or PNG graphics.
- **Aggregations & Grouping**: Full relational support for `COUNT(*)`, `COUNT(col)`, and multi-attribute `GROUP BY` grouping with strict semantic type validation.

### Open Limitations & Future Work
- **Supported Formats**: Currently focused on CycloneDX JSON (versions 1.2–1.6+). Can be extended in the future to parse CycloneDX XML SBOMs or other standard formats such as SPDX (SPDX 2.3 / 3.0).
- **Extended Aggregations**: Addition of arithmetic aggregate functions (`SUM`, `AVG`, `MIN`, `MAX`) and a post-aggregation `HAVING` clause filter.
