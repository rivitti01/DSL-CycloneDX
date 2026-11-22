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
  `SELECT`, `FROM`, `WHERE`, `GROUP`, `ORDER`, `BY`, `ASC`, `DESC`, `LIMIT`, `IN`, `COUNT`
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

Keywords are **soft**: most of them can also be used as column names (e.g. `WHERE severity = HIGH`,
`SELECT type, COUNT(*) ...`). Only the keywords that start a different construct in the same position
are **reserved** as column-name heads: `NOT`, `COUNT` and the six severity levels (see `ColumnName` in §2.5).
After a `.` every keyword is accepted as a field name (e.g. `metadata.component.type`).

### 1.3 Identifiers and Symbols
```ebnf
Identifier      ::= ( Letter | '_' ) ( Letter | Digit | '_' | '-' )*
Letter          ::= [a-zA-Z]
Digit           ::= [0-9]
WhiteSpace      ::= ( ' ' | '\t' | '\r' | '\n' )+
CommentSingle   ::= ( '--' | '//' ) [^\n]* ( '\n' | EOF )
CommentMulti    ::= '/*' ( [^*] | '*'+ [^*/] )* '*'+ '/'

Star            ::= '*'
Comma           ::= ','
Dot             ::= '.'
Semicolon       ::= ';'
LParen          ::= '('
RParen          ::= ')'

Equal           ::= '='
NotEqual        ::= '!='
Less            ::= '<'
LessEqual       ::= '<='
Greater         ::= '>'
GreaterEqual    ::= '>='
```

### 1.4 Literals
```ebnf
StringLiteral   ::= '"' ( [^"\\] | EscapeSeq )* '"'
                  | "'" ( [^'\\] | EscapeSeq )* "'"

EscapeSeq       ::= '\' ( 'n' | 't' | 'r' | '\\' | '"' | "'" )

IntegerLiteral  ::= Digit+
FloatLiteral    ::= Digit+ '.' Digit+
BooleanLiteral  ::= 'true' | 'false'          (* case-insensitive, like keywords *)
```

---

## 2. Syntactic Grammar

The grammar below is **LL(1)**: every choice point (`|`, `[ ... ]`, `( ... )*`) can be decided by
looking at the next token only. It describes exactly the language accepted by the recursive-descent
parser in `src/parser/parser.cpp`, and it is checked automatically by `tools/check_ll1.py` (see §3).

Notation: `"KEYWORD"` and `"symbol"` are terminals, `[ X ]` is an optional `X`, `( X )*` is zero or more
`X`, `(* ... *)` is a comment. An alternative with only a comment is the empty string (ε).

### 2.1 Program Structure
A program is a sequence of statements. The `;` is an optional statement terminator:
```ebnf
Program         ::= ( Statement [ ";" ] )* EOF

Statement       ::= SelectStmt
                  | WhoUsesStmt
                  | FindStmt
                  | ShowTreeStmt
                  | AssertStmt

InClause        ::= "IN" StringLiteral            (* SBOM file the statement runs on *)
WhereClause     ::= "WHERE" Expression
```

---

### 2.2 Basic SQL-like Query (`SELECT`)
The optional clauses always appear in the order `WHERE`, `GROUP BY`, `ORDER BY`, `LIMIT`.
A **single** `IN` clause may be written at one of four points: right after `FROM`, after `WHERE`,
after `GROUP BY`, or at the very end.
```ebnf
SelectStmt      ::= "SELECT" ProjectionList "FROM" CollectionRef SelectTail

ProjectionList  ::= "*" | ProjectionItem ( "," ProjectionItem )*
ProjectionItem  ::= ColumnPath | AggregateExpr
AggregateExpr   ::= "COUNT" "(" ( "*" | ColumnPath ) ")"
CollectionRef   ::= ColumnPath

GroupByClause   ::= "GROUP" "BY" ColumnPath ( "," ColumnPath )*
OrderByClause   ::= "ORDER" "BY" ProjectionItem [ "ASC" | "DESC" ]
LimitClause     ::= "LIMIT" IntegerLiteral

(* SelectTail, SelectTailW and SelectTailG mean "no IN clause read yet" after FROM, WHERE and
   GROUP BY respectively. Once the IN clause is read, the remaining clauses cannot contain another
   one. SelectTailO never starts with IN: an IN before ORDER BY / LIMIT belongs to the alternative
   that reads it first. *)
SelectTail      ::= InClause [ WhereClause ] [ GroupByClause ] [ OrderByClause ] [ LimitClause ]
                  | WhereClause SelectTailW
                  | GroupByClause SelectTailG
                  | SelectTailO

SelectTailW     ::= InClause [ GroupByClause ] [ OrderByClause ] [ LimitClause ]
                  | GroupByClause SelectTailG
                  | SelectTailO

SelectTailG     ::= InClause [ OrderByClause ] [ LimitClause ]
                  | SelectTailO

SelectTailO     ::= OrderByClause [ LimitClause ] [ InClause ]
                  | LimitClause [ InClause ]
                  | (* empty *)
```

---

### 2.3 Advanced Security Constructs

#### `WHO USES` (Reverse Dependency Lookup)
Finds all components and the main root application that depend on a target library.
```ebnf
WhoUsesStmt     ::= "WHO" "USES" TargetRef [ "TRANSITIVE" | "DIRECT" ] [ InClause ]

TargetRef       ::= StringLiteral | Identifier
```

#### `FIND VULNERABLE` and `FIND BLAST RADIUS`
Both statements start with `FIND`, so the common prefix is factored out and the second token
(`VULNERABLE` or `BLAST`) selects the statement.
```ebnf
FindStmt        ::= "FIND" ( FindVulnerableRest | BlastRadiusRest )
```

**`FIND VULNERABLE`** (Cross-domain Relational Join) selects components or libraries by correlating
the components table with the CycloneDX vulnerability catalog (VEX/VDR).
```ebnf
FindVulnerableRest ::= "VULNERABLE" ( "COMPONENTS" | "LIBRARIES" )
                       [ SeverityFilter ]
                       [ WhereClause ]
                       [ InClause ]

SeverityFilter  ::= "SEVERITY" [ CompOp ] SeverityLevel
SeverityLevel   ::= "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "NONE"
```

**`FIND BLAST RADIUS`** (Supply Chain Impact Analysis) computes the blast radius of a vulnerability
along the transitive dependency chain up to the root application.
```ebnf
BlastRadiusRest ::= "BLAST" "RADIUS" "OF" TargetRef [ InClause ]
```

#### `SHOW TREE` (Forward Dependency Graph)
Visualizes the hierarchical dependency tree starting from a root node up to a specified depth.
```ebnf
ShowTreeStmt    ::= "SHOW" ( "TREE" | "DEPENDENCIES" )
                    [ "OF" TargetRef ]
                    [ "DEPTH" IntegerLiteral ]
                    [ InClause ]
```

#### `ASSERT NO` (Policy Enforcement & CI/CD Gatekeeping)
Enforces security and architectural compliance policies across vulnerabilities, components, or
libraries. If any offending record is found, execution ends with exit code `1` and reports the
violating records; otherwise it ends with exit code `0` (exit code `2` is reserved for errors).
As in `SELECT`, a single `IN` clause may appear right after the target or at the end.
```ebnf
AssertStmt      ::= "ASSERT" "NO" AssertTarget AssertTail

AssertTarget    ::= "VULNERABILITIES" | "COMPONENTS" | "LIBRARIES"

AssertTail      ::= InClause [ AssertSeverity ] [ WhereClause ]
                  | AssertSeverity [ WhereClause ] [ InClause ]
                  | WhereClause [ InClause ]
                  | (* empty *)

AssertSeverity  ::= "SEVERITY" [ CompOp ] ( SeverityLevel | NumberLiteral )
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

### 2.5 Column Paths and Soft Keywords

```ebnf
ColumnPath      ::= ColumnName ( "." FieldName )*

ColumnName      ::= Identifier | SoftKeyword
FieldName       ::= Identifier | SoftKeyword | "NOT" | "COUNT" | SeverityLevel

(* Every keyword except NOT, COUNT and the severity levels, which would clash with
   NotExpr, AggregateExpr and Literal respectively. *)
SoftKeyword     ::= "SELECT" | "FROM" | "WHERE" | "GROUP" | "BY" | "ORDER" | "ASC" | "DESC"
                  | "LIMIT" | "IN" | "WHO" | "USES" | "TRANSITIVE" | "DIRECT" | "FIND"
                  | "VULNERABLE" | "COMPONENTS" | "LIBRARIES" | "VULNERABILITIES" | "SEVERITY"
                  | "SHOW" | "TREE" | "DEPENDENCIES" | "OF" | "DEPTH" | "BLAST" | "RADIUS"
                  | "ASSERT" | "NO" | "AND" | "OR" | "CONTAINS" | "MATCHES" | "LIKE"
```

---

## 3. Grammar Properties

1. **LL(1)**: for every non-terminal, the alternatives have disjoint FIRST sets, and every
   alternative that can derive ε has a FIRST set disjoint from the FOLLOW set of the non-terminal.
   The recursive-descent parser therefore never backtracks and decides each step from one token.
   The property is checked mechanically by computing FIRST/FOLLOW sets over the EBNF of §2:
   ```bash
   python3 tools/check_ll1.py docs/grammar.md
   ```
   The CI workflow runs this check, so a change that breaks LL(1) fails the build.
2. **Left-associative**: Binary operators are left-associative.
3. **Precedence climbing**: The parser recognizes expressions (§2.4) with **Pratt parsing**
   (precedence climbing), which gives linear O(N) parsing time and keeps precedence in one table.
   It builds the same trees as the `OrExpr` / `AndExpr` / `NotExpr` / `ComparisonExpr` hierarchy.

### 3.1 Conflicts removed from earlier versions of this grammar
Earlier versions of this document said the grammar was LL(1), but four rules were not:

| Rule (old form) | Conflict | Fix |
| :--- | :--- | :--- |
| `SelectStmt ::= ... [ "IN" s ] [ "WHERE" e ] [ "IN" s ] ... [ "IN" s ]` | **FIRST/FOLLOW** on `IN`: if `WHERE` is missing, an `IN` after `FROM` could be the first or the second optional clause. The rule was also **ambiguous**, since `SELECT * FROM c IN "a"` had three parse trees, and no ambiguous grammar is LL(k). The parser got around this with a context check (`!stmt->bom_path`). | `SelectTail*` non-terminals that track whether the `IN` clause has been read (§2.2). |
| `Statement ::= ... \| FindVulnerableStmt \| BlastRadiusStmt` (both start with `"FIND"`) | **FIRST/FIRST** on `FIND` | Left factoring: `FindStmt ::= "FIND" ( FindVulnerableRest \| BlastRadiusRest )`. |
| `Program ::= Statement ( ";" Statement )* [ ";" ] EOF` | **FIRST/FOLLOW** on `;`: after a `;` it is unclear whether another statement or the trailing `;` follows | `Program ::= ( Statement [ ";" ] )* EOF`, which is what the parser implements. |
| `ColumnPath ::= Identifier ...` while the parser accepted any keyword | The parser accepted a language larger than the grammar, and keywords such as `NOT`, `COUNT` and `HIGH` had two meanings in the same position | Soft-keyword rules in §2.5; the parser now rejects reserved keywords as column-name heads. |

`ASSERT NO` had the same undocumented "IN in two positions" behavior as `SELECT`. It is now
described by `AssertTail` (§2.3).
