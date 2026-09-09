# Architettura del Compilatore CycloneDX Query DSL

Questo documento descrive l'architettura tecnica, le scelte progettuali e la pipeline di compilazione del **CycloneDX Query DSL**, sviluppato in C++20 per il corso di **Formal Languages and Compilers** (Politecnico di Milano).

---

## 1. Visione d'Insieme della Pipeline

Il sistema è strutturato come un vero e proprio compilatore a più stadi, separando nettamente l'analisi del linguaggio dalla rappresentazione intermedia e dall'esecuzione:

```
                            [ Codice Sorgente DSL ]
                                       |
                                       v
                             +-------------------+
                             |       Lexer       |   (Scansione lessicale, Line/Col)
                             +-------------------+
                                       | Token Stream
                                       v
                             +-------------------+
                             |      Parser       |   (Recursive Descent + Pratt Parser)
                             +-------------------+
                                       |
                                       v
                             +-------------------+
                             |        AST        |   (Abstract Syntax Tree C++20)
                             +-------------------+
                                       |
                                       v
                             +-------------------+
                             | Semantic Analysis |   (Type checking, Schema Catalog)
                             +-------------------+
                                       | AST Validato
                                       v
                             +-------------------+
                             |  Query Lowering   |   (Trasformazione High-Level -> IR)
                             +-------------------+
                                       |
                                       v
                             +-------------------+
                             |  Intermediate Rep |   (Piano Relazionale & Grafo)
                             +-------------------+
                                       |
                     +-----------------+-----------------+
                     |                                   |
                     v                                   v
          +---------------------+             +---------------------+
          | sbom-utility CodeGen|             |   Native Engine C++ |
          | - Generazione CLI   |             | - In-memory Graph   |
          | - Offloading CLI    |             | - Hash Join / BFS   |
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

## 2. Dettaglio delle Fasi del Compilatore

### 2.1 Fase 1: Analisi Lessicale (`Lexer`)
- **Responsabilità**: Converte lo stream di caratteri sorgente in una sequenza ordinata di token tipizzati (`Token`).
- **Peculiarità implementative**:
  - Tracciamento della posizione sorgente mediante `SourceLocation` (file, linea, colonna, offset assoluto).
  - Riconoscimento case-insensitive delle parole chiave (es. `SELECT`, `Select`, `select`).
  - Supporto per commenti a riga singola (`--`, `//`) e multiriga (`/* ... */`).
  - Gestione avanzata delle stringhe con sequenze di escape (`\n`, `\t`, `\"`, `\'`, `\\`).
  - Riconoscimento di identificatori composti contenenti trattini (es. `bom-ref`, `cvss-severity`).

### 2.2 Fase 2: Analisi Sintattica (`Parser`)
- **Responsabilità**: Verifica che la sequenza di token rispetti la grammatica formale ed emette l'albero sintattico astratto (`AST`).
- **Scelte architetturali**:
  - **Recursive Descent** per la struttura degli enunciati: garantisce una grammatica LL(1) deterministica, modulare ed estendibile.
  - **Pratt Parsing (Precedence Climbing)** per le espressioni nella clausola `WHERE`:
    - Permette di gestire con estrema eleganza e prestazioni ottimali $O(N)$ le precedenze degli operatori binari (`OR` < `AND` < `NOT` < confronti < primari).
    - Evita l'esplosione di nodi intermedi tipica delle grammatiche canoniche a molti livelli.
  - **Error Recovery**: Meccanismo di sincronizzazione in panic-mode al raggiungimento del token `;` o dell'istruzione successiva.

### 2.3 Fase 3: Abstract Syntax Tree (`AST`) e Pattern Visitor
- **Responsabilità**: Rappresentazione formale e tipizzata della query.
- **Gerarchia C++20**:
  - `ASTNode` (classe base astratta con `SourceLocation`).
  - `StatementNode`: `SelectStatement`, `WhoUsesStatement`, `FindVulnerableStatement`, `ShowTreeStatement`, `BlastRadiusStatement`.
  - `ExpressionNode`: `BinaryOpExpr`, `UnaryOpExpr`, `ColumnRefExpr`, `LiteralExpr`.
- **Pattern Visitor (`ASTVisitor`)**:
  - Disaccoppia la struttura dati dell'albero dalle operazioni su di esso.
  - Utilizzato da `ASTPrinter`, `TypeChecker` e `QueryLowerer`.

### 2.4 Fase 4: Analisi Semantica e Type Checking (`Semantic Analysis`)
- **Responsabilità**: Verifica la correttezza semantica prima della compilazione in IR:
  - **Schema Catalog**: Verifica che le collezioni e i campi appartengano allo standard CycloneDX (`components`, `vulnerabilities`, `dependencies`, `metadata.component`).
  - **Type Checking**: Verifica la compatibilità di tipo negli operatori relazionali e logici (es. blocca confronti tra stringhe e interi con operatori d'ordine).
  - **Validazione vincoli**: Assicura che parametri come `LIMIT` e `DEPTH` siano numeri interi positivi, e che i livelli di severità appartengano al dominio CVSS (`CRITICAL`, `HIGH`, ecc.).

### 2.5 Fase 5: Intermediate Representation (IR) e Query Lowering
- **Responsabilità**: Il cuore teorico del compilatore. Traduce (abbassa) costrutti ad alto livello di astrazione semantica in un piano di esecuzione algebrico composto da primitive relazionali e di grafo:
  - `IRScan`: Scansione della collezione SBOM.
  - `IRFilter`: Filtro predicativo su tuple.
  - `IRProject`: Proiezione e ridenominazione attributi.
  - `IRSort` e `IRLimit`: Ordinamento e troncamento.
  - `IRHashJoin`: Join equi-relazionale (es. `affects == bom-ref`).
  - `IRGraphTraverse`: Chiusura transitiva diretta/inversa sul grafo delle dipendenze.
  - `IRBlastRadius`: Calcolo metriche di impatto e raggiungibilità sistemica.

### 2.6 Fase 6: Dual Backend Esecutivo
Per conciliare le indicazioni del docente e superare le limitazioni intrinseche del tool ufficiale `sbom-utility`:
1. **`SbomUtilityCodeGen`**:
   - Analizza il piano IR. Se la query è compatibile con le primitive di `sbom-utility` (scansione + filtro semplice per uguaglianze), sintetizza il comando CLI shell corrispondente:
     `sbom-utility query --input-file bom.json --from components --select name,version --where "type=library"`
   - Se richiesto, esegue il processo via pipe POSIX e acquisisce il JSON di output.
2. **`NativeEngine` (In-Memory CycloneDX Engine in C++20)**:
   - Motore nativo a zero dipendenze esterne di runtime.
   - Carica il JSON CycloneDX e costruisce strutture dati indicizzate:
     - Tabella hash `bom-ref -> Component` $O(1)$.
     - Indice inverso `name -> bom-ref` $O(1)$.
     - Grafo diretto delle adiacenze $A \rightarrow B$.
     - Grafo inverso delle adiacenze $B \rightarrow A$ (fondamentale per `WHO USES`).
   - Esegue algoritmi di grafo (BFS/DFS per chiusura transitiva con complessità $O(V + E)$).
   - Esegue hash join in memoria in $O(L + R)$.

---

## 3. Complessità Computazionale

| Operazione | Algoritmo | Complessità Temporale | Complessità Spaziale |
| :--- | :--- | :--- | :--- |
| **Lexing** | Scansione lineare a singolo passaggio | $O(N)$ caratteri | $O(T)$ token |
| **Parsing** | Recursive Descent + Pratt Parser | $O(T)$ token | $O(T)$ nodi AST |
| **Type Checking** | Visitor traversal | $O(A)$ nodi AST | $O(1)$ ausiliario |
| **Lowering** | Generazione piano IR | $O(A)$ nodi AST | $O(K)$ nodi IR |
| **Indicizzazione SBOM** | Caricamento JSON + hash indexing | $O(C + D + V)$ | $O(C + D + V)$ |
| **Query Base (Filter/Project)**| Scansione sequenziale | $O(C)$ | $O(R)$ risultati |
| **Reverse Lookup (`WHO USES`)**| BFS su grafo inverso `reverse_graph` | $O(V + E)$ | $O(V)$ visited set |
| **Relational Join (`FIND VULN`)**| Hash Join su `affects <-> bom-ref` | $O(V_{uln} + C_{omp})$ | $O(C_{omp})$ hash table |
| **Blast Radius** | BFS inversa + calcolo percentuale | $O(V + E)$ | $O(V)$ |

---

## 4. Modalità di Ispezione Interna (`--explain`)
Il compilatore include una modalità `--explain` che stampa l'esito di ogni singola fase del processo di compilazione:
1. Stream di token con posizioni;
2. Albero AST pretty-printed;
3. Resoconto della validazione semantica;
4. Albero del piano di esecuzione IR;
5. Comando `sbom-utility` generato o motivazione tecnica del fallback sul motore nativo.
