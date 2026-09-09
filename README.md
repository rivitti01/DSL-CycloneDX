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
  - [Basic SQL-like Queries](#1-basic-sql-like-queries)
  - [Advanced Security Constructs](#2-advanced-security-constructs-30l)
- [Requirements and Build](#requirements-and-build)
- [Running Tests](#running-tests)
- [CLI Guide](#cli-guide)
  - [Explain Mode (`--explain`)](#explain-mode---explain)
  - [Interactive Shell (REPL)](#interactive-shell-repl)
- [Complete Documentation](#complete-documentation)
- [Limitations and Future Work](#limitations-and-future-work)

---

## Project Overview

A Software Bill of Materials (SBOM) is the formal inventory of all software components, dependencies, and known vulnerabilities of an application. The **CycloneDX** format (OWASP) is one of the leading industry standards.

This project implements a modular C++20 compiler and interpreter featuring:
1. **A SQL-like query language** to selectively query CycloneDX collections (`components`, `vulnerabilities`, `dependencies`, `metadata.component`).
2. **High-level software security semantic constructs** (`WHO USES`, `FIND VULNERABLE`, `SHOW TREE`, `FIND BLAST RADIUS`).
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
[ Intermediate Rep (IR) ]  → Scan, Filter, Project, Sort, Limit, HashJoin, GraphTraverse, BlastRadius
      ↓
  +---+---------------------------+
  |                               |
  v                               v
[ sbom-utility CodeGen ]      [ Native CycloneDX Engine ]
(CLI command generation)       (In-memory execution with graphs & hash indexes)
  |                               |
  +---------------+---------------+
                  ↓
          [ Query Results ]   (ASCII Table, JSON, Hierarchical Tree)
```

For more details, consult [docs/architecture.md](docs/architecture.md).

---

## Language Features

### 1. Basic SQL-like Queries
Allows projecting and filtering components, vulnerabilities, and dependencies using comparison and string pattern matching operators (`=`, `!=`, `<`, `>`, `LIKE`, `CONTAINS`):
```sql
SELECT name, version, purl
FROM components
IN "bom.json"
WHERE type = 'library' AND (name LIKE 'exp%' OR purl CONTAINS 'lodash')
ORDER BY name ASC
LIMIT 10;
```

### 2. Advanced Security Constructs (30L)

| Construct | Security Problem Solved | Lowered IR Plan |
| :--- | :--- | :--- |
| `WHO USES "lib" [TRANSITIVE];` | Identifies all components and the root application depending on a library. | `Project -> HashJoin -> GraphTraverse(Reverse) -> Scan(dependencies)` |
| `FIND VULNERABLE LIBRARIES SEVERITY >= HIGH;` | Performs relational join between vulnerability catalog (VEX/VDR) and components. | `Project -> HashJoin(affects == bom-ref) -> Filter(vulns) / Filter(comps)` |
| `SHOW TREE OF "app" DEPTH 2;` | Visual inspection of direct and transitive dependency hierarchy. | `Project -> HashJoin -> GraphTraverse(Forward, depth=2) -> Scan(dependencies)` |
| `FIND BLAST RADIUS OF "CVE-...";` | Computes supply chain impact percentage and root application exposure. | `BlastRadius -> ReverseReachability -> Scan(vulnerabilities)` |
| `ASSERT NO VULNERABILITIES SEVERITY >= HIGH;` | CI/CD gatekeeping: returns exit code `0` on compliance or `1` with violating records. | `Project -> HashJoin -> Filter(vulns) -> Scan(components)` |

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

The automated test suite covers each phase of the compiler:
- `test_lexer`: token scanning, comment handling, escape strings, lexical errors.
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

```bash
# Execute inline query
./build/sbom-dsl -c "SELECT name, version FROM components;" -b tests/fixtures/sample_cyclonedx.json

# Execute query from file
./build/sbom-dsl examples/who_uses.dsl

# Output in JSON format
./build/sbom-dsl examples/basic_select.dsl --format json

# Output in tree format
./build/sbom-dsl examples/show_tree.dsl --format tree
```

### Explain Mode (`--explain`)
Ideal for demonstration and academic evaluation of the compiler:
```bash
./build/sbom-dsl examples/basic_select.dsl --explain
```
Displays in the terminal:
1. `[PHASE 1]` Tokens generated by the Lexer (`line:col`);
2. `[PHASE 2]` Abstract Syntax Tree (`AST`);
3. `[PHASE 3]` Semantic Analysis & Type Checking report;
4. `[PHASE 4]` Intermediate Representation (`IR`) algebraic execution plan;
5. `[PHASE 5]` Target code generated for `sbom-utility` or rationale for routing to the Native Engine;
6. `[EXECUTION RESULTS]` Formatted tabular output.

### Interactive Shell (REPL)
Can be launched without arguments or with `-i`:
```bash
./build/sbom-dsl -i
```
```text
CycloneDX Query DSL Interactive Shell (REPL)
Type your queries followed by ';' or 'exit'/'quit' to exit.
Commands: ':explain [on|off]', ':bom <file>', ':format [table|json|tree]'

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
```

---

## Complete Documentation

The [`docs/`](docs/) directory contains detailed monographic documentation:
- [docs/sbom_utility_analysis.md](docs/sbom_utility_analysis.md): Preliminary study of CycloneDX and `sbom-utility` limitations (Phase 0).
- [docs/architecture.md](docs/architecture.md): Compiler architecture, pipeline, and computational complexity.
- [docs/grammar.md](docs/grammar.md): Complete EBNF formal grammar, tokens, and operator precedence.
- [docs/language.md](docs/language.md): User reference manual covering all supported statements.
- [docs/semantics.md](docs/semantics.md): Data model, CycloneDX catalog, and type system inference rules.
- [docs/advanced-features.md](docs/advanced-features.md): Theoretical details of advanced security constructs and lowering algorithms.
- [docs/examples.md](docs/examples.md): Test cases with queries, execution examples, and `--explain` snippets.

---

## Limitations and Future Work
- **Supported Formats**: Currently focused on CycloneDX JSON (versions 1.2–1.6+). Can be extended in the future to parse XML SBOMs or SPDX 3.0.
- **Query Optimizer**: Potential introduction of a rule-based IR optimization pass (Predicate Pushdown before Joins, Projection Pushdown).
- **Graph Export**: Support exporting `SHOW TREE` results to Graphviz DOT files or SVG vector graphics.
