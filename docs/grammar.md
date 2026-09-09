# Grammatica Formale (EBNF) del CycloneDX Query DSL

Questo documento specifica la sintassi e la grammatica formale del Domain Specific Language (DSL) per l'interrogazione di Software Bill of Materials (SBOM) CycloneDX, formalizzata in **Extended Backus-Naur Form (EBNF)**.

---

## 1. Analisi Lessicale (Lexical Grammar)

### 1.1 Spazi Bianchi e Commenti
Gli spazi bianchi (spazi, tabulazioni, ritorni a capo) fungono da delimitatori di token e vengono scartati durante la scansione:
- `Whitespace ::= ( ' ' | '\t' | '\r' | '\n' )+`
- **Commenti a riga singola (stile SQL)**: `-- commento fino a fine riga`
- **Commenti a riga singola (stile C++)**: `// commento fino a fine riga`
- **Commenti multiriga (stile C/C++)**: `/* commento multiriga */`

### 1.2 Parole Chiave (Keywords)
Il lexer riconosce le parole chiave in modo **case-insensitive** (es. `SELECT`, `Select`, `select` sono equivalenti):

- **Query Base SQL-like**:
  `SELECT`, `FROM`, `WHERE`, `ORDER`, `BY`, `ASC`, `DESC`, `LIMIT`, `IN`
- **Costrutti Avanzati di Sicurezza**:
  `WHO`, `USES`, `TRANSITIVE`, `DIRECT`
  `FIND`, `VULNERABLE`, `COMPONENTS`, `LIBRARIES`, `SEVERITY`
  `SHOW`, `TREE`, `DEPENDENCIES`, `OF`, `DEPTH`
  `BLAST`, `RADIUS`
- **Operatori Logici e Predicati**:
  `AND`, `OR`, `NOT`, `CONTAINS`, `MATCHES`, `LIKE`
- **Livelli di Severità CVSS**:
  `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `NONE`

### 1.3 Identificatori e Simboli
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

### 1.4 Letterali (Literals)
```ebnf
StringLiteral   ::= '"' ( [^"\\] | EscapeSeq )* '"'
                  | "'" ( [^'\\] | EscapeSeq )* "'"

EscapeSeq       ::= '\' ( 'n' | 't' | 'r' | '\\' | '"' | "'" )

IntegerLiteral  ::= Digit+
FloatLiteral    ::= Digit+ '.' Digit+
BooleanLiteral  ::= 'true' | 'false' | 'TRUE' | 'FALSE'
```

---

## 2. Grammatica Sintattica (Syntactic Grammar)

### 2.1 Struttura del Programma
Un programma DSL è composto da una sequenza di istruzioni separate da punto e virgola:
```ebnf
Program         ::= Statement ( ';' Statement )* [ ';' ] EOF

Statement       ::= SelectStmt
                  | WhoUsesStmt
                  | FindVulnerableStmt
                  | ShowTreeStmt
                  | BlastRadiusStmt
```

---

### 2.2 Query Base SQL-like (`SELECT`)
```ebnf
SelectStmt      ::= "SELECT" ProjectionList
                    "FROM" CollectionRef
                    [ "IN" StringLiteral ]
                    [ "WHERE" Expression ]
                    [ "IN" StringLiteral ]
                    [ "ORDER" "BY" ColumnPath [ "ASC" | "DESC" ] ]
                    [ "LIMIT" IntegerLiteral ]
                    [ "IN" StringLiteral ]

ProjectionList  ::= "*" | ColumnPath ( "," ColumnPath )*
CollectionRef   ::= Identifier ( "." Identifier )*
ColumnPath      ::= Identifier ( "." Identifier )*
```

---

### 2.3 Costrutti Avanzati di Sicurezza

#### `WHO USES` (Reverse Dependency Lookup)
Trova tutte le componenti e l'applicazione principale che dipendono da una libreria bersaglio.
```ebnf
WhoUsesStmt     ::= "WHO" "USES" TargetRef [ "TRANSITIVE" | "DIRECT" ] [ "IN" StringLiteral ]

TargetRef       ::= StringLiteral | Identifier
```

#### `FIND VULNERABLE` (Cross-domain Relational Join)
Seleziona componenti o librerie correlando la tabella dei componenti con il catalogo delle vulnerabilità CycloneDX (VEX/VDR).
```ebnf
FindVulnerableStmt ::= "FIND" "VULNERABLE" ( "COMPONENTS" | "LIBRARIES" )
                       [ "SEVERITY" [ CompOp ] SeverityLevel ]
                       [ "WHERE" Expression ]
                       [ "IN" StringLiteral ]

SeverityLevel   ::= "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" | "NONE"
```

#### `SHOW TREE` (Forward Dependency Graph)
Visualizza l'albero gerarchico delle dipendenze a partire da una radice fino a una profondità specificata.
```ebnf
ShowTreeStmt    ::= "SHOW" ( "TREE" | "DEPENDENCIES" )
                    [ "OF" TargetRef ]
                    [ "DEPTH" IntegerLiteral ]
                    [ "IN" StringLiteral ]
```

#### `FIND BLAST RADIUS` (Supply Chain Impact Analysis)
Calcola il raggio d'impatto di una vulnerabilità lungo la catena di dipendenze transitive fino all'applicazione radice.
```ebnf
BlastRadiusStmt ::= "FIND" "BLAST" "RADIUS" "OF" TargetRef [ "IN" StringLiteral ]
```

---

### 2.4 Espressioni e Predicati (`WHERE`)

Le espressioni supportano la precedenza classica degli operatori booleani e relazionali:
- `OR` (precedenza minima)
- `AND`
- `NOT`
- Operatori di confronto e stringa (`=`, `!=`, `<`, `<=`, `>`, `>=`, `CONTAINS`, `MATCHES`, `LIKE`)
- Espressioni primarie e parentesi `( ... )` (precedenza massima)

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

## 3. Proprietà della Grammatica
1. **Assenza di ambiguità**: La sintassi delle istruzioni è deterministica con lookahead $k=1$ (LL(1)).
2. **Associatività a sinistra**: Gli operatori binari sono associativi a sinistra (`left-associative`).
3. **Precedenza climbing**: Le espressioni della clausola `WHERE` sono analizzate mediante **Pratt Parsing** (Precedence Climbing), garantendo tempo di parsing lineare $O(N)$ e gestione pulita delle precedenze.
