# CycloneDX Query DSL (Domain Specific Language)

[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://en.wikipedia.org/wiki/C%2B%2B20)
[![CMake](https://img.shields.io/badge/CMake-3.20+-darkcyan.svg)](https://cmake.org/)
[![License](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-Passing%20(100%25)-brightgreen.svg)]()

> Progetto per il corso di **Formal Languages and Compilers** — Politecnico di Milano.  
> Obiettivo: Progettazione e implementazione di un compilatore completo per un Domain Specific Language (DSL) per l'interrogazione e l'analisi di sicurezza di Software Bill of Materials (SBOM) in formato **CycloneDX**.

---

## Indice dei Contenuti
- [Panoramica del Progetto](#panoramica-del-progetto)
- [Architettura del Compilatore](#architettura-del-compilatore)
- [Funzionalità del Linguaggio](#funzionalità-del-linguaggio)
  - [Query Base SQL-like](#1-query-base-sql-like)
  - [Costrutti Avanzati di Sicurezza](#2-costrutti-avanzati-di-sicurezza-30l)
- [Requisiti e Compilazione](#requisiti-e-compilazione)
- [Esecuzione dei Test](#esecuzione-dei-test)
- [Guida alla CLI](#guida-alla-cli)
  - [Modalità Explain (`--explain`)](#modalità-explain---explain)
  - [Sessione Interattiva (REPL)](#sessione-interattiva-repl)
- [Documentazione Completa](#documentazione-completa)
- [Limitazioni e Sviluppi Futuri](#limitazioni-e-sviluppi-futuri)

---

## Panoramica del Progetto

Una Software Bill of Materials (SBOM) è l'inventario formale di tutti i componenti software, le dipendenze e le vulnerabilità note di un'applicazione. Il formato **CycloneDX** (OWASP) è uno dei principali standard industriali.

Questo progetto realizza un compilatore e interprete C++20 modulare che implementa:
1. **Un linguaggio SQL-like** per interrogare in modo selettivo le collezioni CycloneDX (`components`, `vulnerabilities`, `dependencies`, `metadata.component`).
2. **Costrutti semantici di alto livello per la sicurezza del software** (`WHO USES`, `FIND VULNERABLE`, `SHOW TREE`, `FIND BLAST RADIUS`).
3. **Query Lowering formale**: i costrutti di alto livello vengono compilati in un piano algebrico di **Intermediate Representation (IR)** costituito da primitive relazionali e di grafo.
4. **Dual Backend Esecutivo**:
   - **`sbom-utility` Code Generator**: genera ed emette comandi CLI per il tool ufficiale OWASP [`sbom-utility`](https://github.com/CycloneDX/sbom-utility);
   - **Native CycloneDX Engine**: motore C++ in memoria con indici hash e algoritmi di grafo (BFS, cammini, chiusure transitive) che supera le limitazioni del tool Go (che non supporta né join né grafi).

---

## Architettura del Compilatore

La pipeline segue rigorosamente le fasi classiche dell'ingegneria dei compilatori:

```
[ DSL Source ]
      ↓
[ Lexer ]                  → Scansione lessicale con tracciamento riga/colonna (SourceLocation)
      ↓
[ Parser ]                 → Recursive Descent (Statements) + Pratt Parser (Precedenza Espressioni)
      ↓
[ AST ]                    → Abstract Syntax Tree C++20 con Pattern Visitor
      ↓
[ Semantic Analysis ]      → Type Checking e Schema Catalog CycloneDX (v1.2 - v1.6+)
      ↓
[ Query Lowerer ]          → Abbassamento dell'AST in piano IR relazionale/grafo
      ↓
[ Intermediate Rep (IR) ]  → Scan, Filter, Project, Sort, Limit, HashJoin, GraphTraverse, BlastRadius
      ↓
  +---+---------------------------+
  |                               |
  v                               v
[ sbom-utility CodeGen ]      [ Native CycloneDX Engine ]
(Generazione comandi CLI)      (Esecuzione in-memory con grafi e indici hash)
  |                               |
  +---------------+---------------+
                  ↓
          [ Query Results ]   (Tabella ASCII, JSON, Albero gerarchico)
```

Per maggiori dettagli, consultare [docs/architecture.md](docs/architecture.md).

---

## Funzionalità del Linguaggio

### 1. Query Base SQL-like
Permette di proiettare e filtrare componenti, vulnerabilità e dipendenze:
```sql
SELECT name, version, purl
FROM components
IN "bom.json"
WHERE type = 'library' AND (name = 'express' OR name = 'lodash')
ORDER BY name ASC
LIMIT 10;
```

### 2. Costrutti Avanzati di Sicurezza (30L)

| Costrutto | Problema di Sicurezza Risolto | Piano IR Abbassato |
| :--- | :--- | :--- |
| `WHO USES "lib" [TRANSITIVE];` | Identifica tutti i componenti e l'applicazione radice che dipendono da una libreria. | `Project -> HashJoin -> GraphTraverse(Reverse) -> Scan(dependencies)` |
| `FIND VULNERABLE LIBRARIES SEVERITY >= HIGH;` | Esegue il join relazionale tra catalogo vulnerabilità (VEX/VDR) e componenti. | `Project -> HashJoin(affects == bom-ref) -> Filter(vulns) / Filter(comps)` |
| `SHOW TREE OF "app" DEPTH 2;` | Ispezione visiva della gerarchia delle dipendenze dirette e transitive. | `Project -> HashJoin -> GraphTraverse(Forward, depth=2) -> Scan(dependencies)` |
| `FIND BLAST RADIUS OF "CVE-...";` | Calcola percentuale di impatto della supply chain ed esposizione della root app. | `BlastRadius -> ReverseReachability -> Scan(vulnerabilities)` |

Per maggiori dettagli, consultare [docs/advanced-features.md](docs/advanced-features.md) e [docs/language.md](docs/language.md).

---

## Requisiti e Compilazione

### Requisiti
- Compilatore C++ moderno con supporto completo **C++20** (AppleClang 15+, GCC 11+, Clang 13+);
- **CMake 3.20+**;
- Connessione ad internet per il primo fetch automatico delle dipendenze header-only (`nlohmann/json` e `doctest` via `FetchContent`).

### Compilazione
```bash
# 1. Clona il repository
git clone https://github.com/rivitti01/DSL-CycloneDX.git
cd DSL-CycloneDX

# 2. Configura CMake
cmake -B build -DCMAKE_BUILD_TYPE=Release

# 3. Compila libreria, CLI e test suite
cmake --build build -j4
```
L'eseguibile principale generato sarà `build/sbom-dsl`.

---

## Esecuzione dei Test

La suite di test automatizzati copre ogni fase del compilatore:
- `test_lexer`: scansione token, gestione commenti, stringhe con escape, errori lessicali.
- `test_parser`: parsing ricorsivo, precedenze di Pratt per espressioni complesse, errori sintattici.
- `test_semantic`: validazione schema catalog, type checking di comparatori e tipi disomogenei.
- `test_lowering`: generazione accurata dei piani algebrici IR relazionali e di grafo.
- `test_backend`: esecuzione su SBOM CycloneDX reale, reverse lookup, join relazionale, raggio d'impatto.
- `test_e2e`: test end-to-end completi da sorgente DSL a risultato formattato.

Per eseguire tutti i test tramite CTest:
```bash
ctest --test-dir build --output-on-failure
```

---

## Guida alla CLI

```bash
# Esecuzione query inline
./build/sbom-dsl -c "SELECT name, version FROM components;" -b tests/fixtures/sample_cyclonedx.json

# Esecuzione query da file
./build/sbom-dsl examples/who_uses.dsl

# Output in formato JSON
./build/sbom-dsl examples/basic_select.dsl --format json

# Output in formato albero
./build/sbom-dsl examples/show_tree.dsl --format tree
```

### Modalità Explain (`--explain`)
Ideale per la dimostrazione e revisione accademica del compilatore:
```bash
./build/sbom-dsl examples/basic_select.dsl --explain
```
Visualizza a terminale:
1. `[PHASE 1]` Token generati dal Lexer (`line:col`);
2. `[PHASE 2]` Albero Sintattico Astratto (`AST`);
3. `[PHASE 3]` Resoconto di Analisi Semantica e Type Checking;
4. `[PHASE 4]` Piano algebrico Intermediate Representation (`IR`);
5. `[PHASE 5]` Codice target generato per `sbom-utility` o motivazione del routing su Native Engine;
6. `[EXECUTION RESULTS]` Risultato tabulare formattato.

### Sessione Interattiva (REPL)
Avviabile senza argomenti o con `-i`:
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

## Documentazione Completa

La cartella [`docs/`](docs/) contiene la documentazione monografica dettagliata:
- [docs/sbom_utility_analysis.md](docs/sbom_utility_analysis.md): Studio preliminare di CycloneDX e limitazioni di `sbom-utility` (Fase 0).
- [docs/architecture.md](docs/architecture.md): Architettura del compilatore, pipeline e complessità computazionale.
- [docs/grammar.md](docs/grammar.md): Grammatica formale EBNF completa, token e precedenze.
- [docs/language.md](docs/language.md): Manuale di riferimento utente con tutte le istruzioni supportate.
- [docs/semantics.md](docs/semantics.md): Modello dei dati, catalogo CycloneDX e regole di inferenza del type system.
- [docs/advanced-features.md](docs/advanced-features.md): Dettaglio teorico dei costrutti avanzati di sicurezza e algoritmi di lowering.
- [docs/examples.md](docs/examples.md): Esempi di test con query, esecuzioni ed estratti `--explain`.

---

## Limitazioni e Sviluppi Futuri
- **Formati supportati**: Attualmente focalizzato su CycloneDX JSON (versioni 1.2–1.6+). Estendibile in futuro al parsing di SBOM in formato XML o SPDX 3.0.
- **Query Ottimizzatore**: Possibilità di introdurre un pass di ottimizzazione IR basato su regole (Predicate Pushdown prima del Join, Projection Pushdown).
- **Esportazione Grafi**: Supporto all'esportazione dei risultati di `SHOW TREE` in file Graphviz DOT o immagini vettoriali SVG.
