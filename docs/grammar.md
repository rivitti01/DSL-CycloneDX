# CycloneDX Query DSL Formal Grammar (EBNF)

This document specifies the syntax and formal grammar of the Domain Specific Language (DSL) for querying CycloneDX Software Bill of Materials (SBOM), formalized in **Extended Backus-Naur Form (EBNF)**.

---

## 1. Lexical Grammar

### 1.1 Whitespace and Comments
Whitespace characters (spaces, tabs, newlines) serve as token delimiters and are discarded during lexical analysis:
- `Whitespace ::= ( ' ' | '\t' | '\r' | '\n' )+`
- **Single-line comments (SQL style)**: `-- comment to end of line`
- **Single-line comments (C++ style)**: `// comment to end of line`
- **Multi-line comments (C/C++ style)**: `/* multi-line comment */`

### 1.2 Keywords
The lexer recognizes keywords in a **case-insensitive** manner (e.g., `SELECT`, `Select`, and `select` are equivalent):

- **Basic SQL-like Queries**:
  `SELECT`, `FROM`, `WHERE`, `ORDER`, `BY`, `ASC`, `DESC`, `LIMIT`, `IN`
- **Advanced Security Constructs**:
  `WHO`, `USES`, `TRANSITIVE`, `DIRECT`
  `FIND`, `VULNERABLE`, `COMPONENTS`, `LIBRARIES`, `VULNERABILITIES`, `SEVERITY`
  `SHOW`, `TREE`, `DEPENDENCIES`, `OF`, `DEPTH`
  `BLAST`, `RADIUS`
  `ASSERT`, `NO`
- **Logical Operators and Predicates**:
  `AND`, `OR`, `NOT`, `CONTAINS`, `MATCHES`, `LIKE`
- **CVSS Severity Levels**:
  `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `NONE`

### 1.3 Identifiers and Symbols
```ebnf
Identifier      ::= ( Letter | '_' ) ( Letter | Digit | '_' | '-' )*
Letter          ::= [a-zA-Z]
Digit           ::= [0-9]

Star            ::= '*'
Comma           ::= ','
Dot             ::= '.'
Semicolon       ::= ';'
LParen          ::= '('
RParen          ::= ')'
```

### 1.4 Literals
```ebnf
StringLiteral   ::= '"' ( [^"\\] | EscapeSeq )* '"'
                  | "'" ( [^'\\] | EscapeSeq )* "'"

EscapeSeq       ::= '\' ( 'n' | 't' | 'r' | '\\' | '"' | "'" )

IntegerLiteral  ::= Digit+
FloatLiteral    ::= Digit+ '.' Digit+
BooleanLiteral  ::= 'true' | 'false' | 'TRUE' | 'FALSE'
```

---

## 2. Syntactic Grammar

### 2.1 Program Structure
A DSL program consists of a sequence of statements separated by semicolons:
```ebnf
Program         ::= Statement ( ';' Statement )* [ ';' ] EOF

Statement       ::= SelectStmt
                  | WhoUsesStmt
                  | FindVulnerableStmt
                  | ShowTreeStmt
                  | BlastRadiusStmt
                  | AssertStmt
```

---

### 2.2 Basic SQL-like Query (`SELECT`)
```ebnf
SelectStmt      ::= "SELECT" ProjectionList
                    "FROM" CollectionRef
                    [ "IN" StringLiteral ]
                    [ "WHERE" Expression ]
                    [ "IN" StringLiteral ]
                    [ "GROUP" "BY" ColumnPath ( "," ColumnPath )* ]
                    [ "ORDER" "BY" ColumnPath [ "ASC" | "DESC" ] ]
                    [ "LIMIT" IntegerLiteral ]
                    [ "IN" StringLiteral ]

ProjectionList  ::= "*" | ProjectionItem ( "," ProjectionItem )*
ProjectionItem  ::= ColumnPath | AggregateExpr
AggregateExpr   ::= "COUNT" "(" ( "*" | ColumnPath ) ")"
CollectionRef   ::= Identifier ( "." Identifier )*
ColumnPath      ::= Identifier ( "." Identifier )*
```

---

### 2.3 Advanced Security Constructs

#### `WHO USES` (Reverse Dependency Lookup)
Finds all components and the main root application that depend on a target library.
```ebnf
WhoUsesStmt     ::= "WHO" "USES" TargetRef [ "TRANSITIVE" | "DIRECT" ] [ "IN" StringLiteral ]

TargetRef       ::= StringLiteral | Identifier
```

#### `FIND VULNERABLE` (Cross-domain Relational Join)
Selects components or libraries by correlating the components table with the CycloneDX vulnerability catalog (VEX/VDR).
```ebnf
FindVulnerableStmt ::= "FIND" "VULNERABLE" ( "COMPONENTS" | "LIBRARIES" )
                       [ "SEVERITY" [ CompOp ] SeverityLevel ]
                       [ "WHERE" Expression ]
                       [ "IN" StringLiteral ]

SeverityLevel   ::= "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "NONE"
```

#### `SHOW TREE` (Forward Dependency Graph)
Visualizes the hierarchical dependency tree starting from a root node up to a specified depth.
```ebnf
ShowTreeStmt    ::= "SHOW" ( "TREE" | "DEPENDENCIES" )
                    [ "OF" TargetRef ]
                    [ "DEPTH" IntegerLiteral ]
                    [ "IN" StringLiteral ]
```

#### `FIND BLAST RADIUS` (Supply Chain Impact Analysis)
Computes the blast radius of a vulnerability along the transitive dependency chain up to the root application.
```ebnf
BlastRadiusStmt ::= "FIND" "BLAST" "RADIUS" "OF" TargetRef [ "IN" StringLiteral ]
```

#### `ASSERT NO` (Policy Enforcement & CI/CD Gatekeeping)
Enforces security and architectural compliance policies across vulnerabilities, components, or libraries. If any offending records are detected, execution terminates with exit code `1` (or non-zero) and reports violating records; otherwise yields exit code `0`.
```ebnf
AssertStmt      ::= "ASSERT" "NO" AssertTarget
                    [ "SEVERITY" [ CompOp ] ( SeverityLevel | NumberLiteral ) ]
                    [ "WHERE" Expression ]
                    [ "IN" StringLiteral ]

AssertTarget    ::= "VULNERABILITIES" | "COMPONENTS" | "LIBRARIES"
NumberLiteral   ::= IntegerLiteral | FloatLiteral
```

---

### 2.4 Expressions and Predicates (`WHERE`)

Expressions support standard boolean and relational operator precedence:
- `OR` (lowest precedence)
- `AND`
- `NOT`
- Comparison and string operators (`=`, `!=`, `<`, `<=`, `>`, `>=`, `CONTAINS`, `MATCHES`, `LIKE`)
- Primary expressions and parentheses `( ... )` (highest precedence)

```ebnf
Expression      ::= OrExpr

OrExpr          ::= AndExpr ( "OR" AndExpr )*

AndExpr         ::= NotExpr ( "AND" NotExpr )*

NotExpr         ::= "NOT" NotExpr
                  | ComparisonExpr

ComparisonExpr  ::= PrimaryExpr [ CompOp PrimaryExpr ]

PrimaryExpr     ::= ColumnPath
                  | Literal
                  | "(" Expression ")"

CompOp          ::= "=" | "!=" | "<" | "<=" | ">" | ">="
                  | "CONTAINS" | "MATCHES" | "LIKE"

Literal         ::= StringLiteral
                  | IntegerLiteral
                  | FloatLiteral
                  | BooleanLiteral
                  | SeverityLevel
```

---

## 3. Grammar Properties
1. **Unambiguous**: Statement syntax is deterministic with $k=1$ lookahead (LL(1)).
2. **Left-associative**: Binary operators are left-associative.
3. **Precedence climbing**: Expressions within the `WHERE` clause are parsed using **Pratt Parsing** (Precedence Climbing), ensuring linear $O(N)$ parsing time and clean precedence management.
