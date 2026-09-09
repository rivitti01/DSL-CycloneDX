# CycloneDX Query DSL Compiler Architecture

This document describes the technical architecture, design choices, and compilation pipeline of the **CycloneDX Query DSL**, developed in C++20 for the **Formal Languages and Compilers** course (Politecnico di Milano).

---

## 1. Overall Pipeline Architecture

The system is structured as a full multi-stage compiler, cleanly separating language front-end analysis from intermediate representation and execution backends:

```
                            [ DSL Source Code ]
                                     |
                                     v
                           +-------------------+
                           |       Lexer       |   (Lexical scanning, Line/Col)
                           +-------------------+
                                     | Token Stream
                                     v
                           +-------------------+
                           |      Parser       |   (Recursive Descent + Pratt Parser)
                           +-------------------+
                                     |
                                     v
                           +-------------------+
                           |        AST        |   (C++20 Abstract Syntax Tree)
                           +-------------------+
                                     |
                                     v
                           +-------------------+
                           | Semantic Analysis |   (Type checking, Schema Catalog)
                           +-------------------+
                                     | Validated AST
                                     v
                           +-------------------+
                           |  Query Lowering   |   (High-Level -> IR Transformation)
                           +-------------------+
                                     |
                                     v
                           +-------------------+
                           | Intermediate Rep  |   (Relational & Graph Plan)
                           +-------------------+
                                     |
                   +-----------------+-----------------+
                   |                                   |
                   v                                   v
        +---------------------+             +---------------------+
        | sbom-utility CodeGen|             |   Native Engine C++ |
        | - CLI Generation    |             | - In-memory Graph   |
        | - CLI Offloading    |             | - Hash Join / BFS   |
        +---------------------+             +---------------------+
                   |                                   |
                   +-----------------+-----------------+
                                     |
                                     v
                           +-------------------+
                           | Result Formatter  |   (Table, JSON, Tree)
                           +-------------------+
```

---

## 2. Compiler Phases Detail

### 2.1 Phase 1: Lexical Analysis (`Lexer`)
- **Responsibility**: Converts the stream of source characters into an ordered sequence of typed tokens (`Token`).
- **Implementation highlights**:
  - Source position tracking via `SourceLocation` (filename, line, column, absolute offset).
  - Case-insensitive keyword recognition (e.g., `SELECT`, `Select`, `select`).
  - Support for single-line comments (`--`, `//`) and multi-line comments (`/* ... */`).
  - Robust escape sequence handling in string literals (`\n`, `\t`, `\"`, `\'`, `\\`).
  - Recognition of compound hyphenated identifiers (e.g., `bom-ref`, `cvss-severity`).

### 2.2 Phase 2: Syntactic Analysis (`Parser`)
- **Responsibility**: Verifies that the token stream complies with the formal grammar and produces the Abstract Syntax Tree (`AST`).
- **Architectural choices**:
  - **Recursive Descent** for statement structure: ensures a deterministic, modular, and extensible LL(1) grammar.
  - **Pratt Parsing (Precedence Climbing)** for expressions in the `WHERE` clause:
    - Handles binary operator precedence (`OR` < `AND` < `NOT` < comparisons < primaries) with optimal $O(N)$ efficiency.
    - Avoids the exponential explosion of intermediate AST nodes typical of multi-level canonical grammars.
  - **Error Recovery**: Panic-mode synchronization mechanism recovering upon encountering a semicolon `;` or the start of the next statement.

### 2.3 Phase 3: Abstract Syntax Tree (`AST`) and Visitor Pattern
- **Responsibility**: Formal, strongly typed representation of the query.
- **C++20 Class Hierarchy**:
  - `ASTNode` (abstract base class with `SourceLocation`).
  - `StatementNode`: `SelectStatement`, `WhoUsesStatement`, `FindVulnerableStatement`, `ShowTreeStatement`, `BlastRadiusStatement`.
  - `ExpressionNode`: `BinaryOpExpr`, `UnaryOpExpr`, `ColumnRefExpr`, `LiteralExpr`.
- **Visitor Pattern (`ASTVisitor`)**:
  - Decouples tree data structures from traversal operations.
  - Used by `ASTPrinter`, `TypeChecker`, and `QueryLowerer`.

### 2.4 Phase 4: Semantic Analysis and Type Checking (`Semantic Analysis`)
- **Responsibility**: Ensures semantic validity prior to IR compilation:
  - **Schema Catalog**: Verifies that collections and fields conform to the CycloneDX standard (`components`, `vulnerabilities`, `dependencies`, `metadata.component`).
  - **Type Checking**: Checks type compatibility across relational and logical operators (e.g., prevents comparisons between strings and integers using order operators).
  - **Constraint Validation**: Enforces that parameters such as `LIMIT` and `DEPTH` are positive integers, and that severity levels belong to the standard CVSS domain (`CRITICAL`, `HIGH`, etc.).

### 2.5 Phase 5: Intermediate Representation (IR) and Query Lowering
- **Responsibility**: Theoretical core of the compiler. Lowers high-level domain constructs into an algebraic execution plan composed of relational and graph primitives:
  - `IRScan`: Scans an SBOM collection.
  - `IRFilter`: Predicate filtering on tuples.
  - `IRProject`: Attribute projection and renaming.
  - `IRSort` and `IRLimit`: Tuple ordering and truncation.
  - `IRHashJoin`: Relational equi-join (e.g., `affects == bom-ref`).
  - `IRGraphTraverse`: Direct/reverse transitive closure over the dependency graph.
  - `IRBlastRadius`: Computation of blast radius metrics and reachability.

### 2.6 Phase 6: Dual Execution Backend
To balance instructor guidance with overcoming the intrinsic limitations of the official `sbom-utility` tool:
1. **`SbomUtilityCodeGen`**:
   - Inspects the IR plan. If the query is compatible with `sbom-utility` primitives (scan + simple equality filtering), synthesizes the corresponding shell CLI command:
     `sbom-utility query --input-file bom.json --from components --select name,version --where "type=library"`
   - If requested, spawns the process via POSIX pipes and parses the JSON output.
2. **`NativeEngine` (In-Memory CycloneDX Engine in C++20)**:
   - Native engine with zero external runtime dependencies.
   - Parses the CycloneDX JSON and constructs in-memory indexed data structures:
     - Hash table `bom-ref -> Component` in $O(1)$.
     - Inverted index `name -> bom-ref` in $O(1)$.
     - Forward adjacency graph $A \rightarrow B$.
     - Reverse adjacency graph $B \rightarrow A$ (critical for `WHO USES`).
   - Executes graph algorithms (BFS/DFS for transitive closure in $O(V + E)$ complexity).
   - Performs in-memory hash joins in $O(L + R)$ complexity.

---

## 3. Computational Complexity

| Operation | Algorithm | Time Complexity | Auxiliary Space Complexity |
| :--- | :--- | :--- | :--- |
| **Lexing** | Single-pass linear scan | $O(N)$ characters | $O(T)$ tokens |
| **Parsing** | Recursive Descent + Pratt Parser | $O(T)$ tokens | $O(T)$ AST nodes |
| **Type Checking** | Visitor traversal | $O(A)$ AST nodes | $O(1)$ auxiliary |
| **Lowering** | IR plan generation | $O(A)$ AST nodes | $O(K)$ IR nodes |
| **SBOM Indexing** | JSON loading + hash indexing | $O(C + D + V)$ | $O(C + D + V)$ |
| **Basic Query (Filter/Project)**| Sequential scan | $O(C)$ | $O(R)$ results |
| **Reverse Lookup (`WHO USES`)**| BFS on reverse graph (`reverse_graph`) | $O(V + E)$ | $O(V)$ visited set |
| **Relational Join (`FIND VULN`)**| Hash Join on `affects <-> bom-ref` | $O(V_{uln} + C_{omp})$ | $O(C_{omp})$ hash table |
| **Blast Radius** | Reverse BFS + impact percentage | $O(V + E)$ | $O(V)$ |

---

## 4. Internal Inspection Mode (`--explain`)
The compiler features an `--explain` mode that displays the output of each individual compilation phase:
1. Token stream with source coordinates;
2. Pretty-printed AST tree;
3. Semantic validation report;
4. Algebraic IR execution plan tree;
5. Generated `sbom-utility` command or technical rationale for fallback to the native engine.
