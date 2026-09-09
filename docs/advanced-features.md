# Funzionalità Avanzate di Sicurezza e Query Lowering (30L)

Questo documento illustra nel dettaglio le **funzionalità avanzate di sicurezza** introdotte nel CycloneDX Query DSL per soddisfare l'obiettivo del corso **Formal Languages and Compilers** (Politecnico di Milano), dimostrando un processo di compilazione completo attraverso il **Query Lowering** verso un'Intermediate Representation (IR) relazionale e di grafo.

---

## 1. Perché queste funzionalità?

In un'analisi di sicurezza software (Software Supply Chain Security), le sole query tabulari non bastano:
1. **Le dipendenze formano un grafo orientato**: Una libreria vulnerabile non viene quasi mai importata direttamente dal codice sorgente dell'utente, ma viene trascinata dentro da librerie intermedie (dipendenze transitive).
2. **I dati sono distribuiti su più domini**: CycloneDX separa l'inventario dei componenti (`components`), le relazioni di dipendenza (`dependencies`) e gli advisory di sicurezza (`vulnerabilities`).
3. **`sbom-utility` non supporta né join relazionali né analisi di grafi**: Il nostro DSL eleva il livello di astrazione, consentendo all'utente di esprimere query di sicurezza ad alto livello che il compilatore abbassa in piani di esecuzione formali.

---

## 2. Dettaglio dei 5 Costrutti Avanzati

---

### Costrutto 1: `WHO USES "<component>" [TRANSITIVE | DIRECT];`

#### Problema Risolto
Quando viene scoperta una vulnerabilità critica zero-day in una libreria (es. `log4j-core` o `qs`), l'analista deve rispondere istantaneamente: *"Quali moduli e quale applicazione stanno usando questa libreria?"*.

#### Sintassi e Semantica
- Sintassi: `WHO USES "<component-name-or-purl>" [TRANSITIVE | DIRECT] [IN "<file.json>"];`
- Semantica: Trova tutti i nodi antenati nel grafo delle dipendenze che hanno un cammino orientato verso il componente bersaglio.

#### Rappresentazione AST
```cpp
class WhoUsesStatement : public StatementNode {
    std::string target_component;
    bool is_transitive{true};
    std::optional<std::string> bom_path;
};
```

#### Abbassamento (Lowering) in IR
Il Lowerer trasforma il nodo AST in un piano composto da scansione, attraversamento del grafo inverso e hash join:
```
Project(columns=[name, version, type, bom-ref, purl])
  └── HashJoin(on left.ref == right.bom-ref)
        ├── Left Input:
        │     GraphTraverse(target="qs", direction=REVERSE, transitive=true)
        │       └── Scan(collection="dependencies")
        └── Right Input:
              Scan(collection="components")
```

#### Esempio e Risultato
```sql
WHO USES "qs" TRANSITIVE IN "tests/fixtures/sample_cyclonedx.json";
```
Output:
```
+-------------+---------+-------------+----------------------------+----------------------------+
| name        | version | type        | bom-ref                    | purl                       |
+=============+=========+=============+============================+============================+
| body-parser | 1.19.0  | library     | pkg:npm/body-parser@1.19.0 | pkg:npm/body-parser@1.19.0 |
| express     | 4.17.1  | library     | pkg:npm/express@4.17.1     | pkg:npm/express@4.17.1     |
| my-web-app  | 2.1.0   | application | pkg:npm/my-web-app@2.1.0   | -                          |
+-------------+---------+-------------+----------------------------+----------------------------+
Total: 3 row(s) [Backend: Native CycloneDX Engine]
```

---

### Costrutto 2: `FIND VULNERABLE LIBRARIES [SEVERITY >= <level>];`

#### Problema Risolto
`sbom-utility` elenca le vulnerabilità o i componenti in modo disgiunto. `FIND VULNERABLE` esegue un join tra il catalogo delle vulnerabilità e i metadati dei componenti software, permettendo di filtrare per severità minima e tipo di componente.

#### Sintassi e Semantica
- Sintassi: `FIND VULNERABLE (COMPONENTS | LIBRARIES) [SEVERITY [op] <level>] [WHERE <cond>];`
- Semantica: Esegue l'equi-join relazionale tra `vulnerabilities[].affects[].ref` e `components[].bom-ref`.

#### Rappresentazione AST
```cpp
class FindVulnerableStatement : public StatementNode {
    bool libraries_only{false};
    std::optional<BinaryOperator> severity_op;
    std::optional<SeverityLevel> severity_level;
    std::unique_ptr<ExpressionNode> where_clause;
    std::optional<std::string> bom_path;
};
```

#### Abbassamento (Lowering) in IR
```
Project(columns=[name, version, type, vuln_id, severity, score, description])
  └── HashJoin(on left.affects == right.bom-ref)
        ├── Left Input:
        │     Filter(predicate=[ratings.severity >= HIGH])
        │       └── Scan(collection="vulnerabilities")
        └── Right Input:
              Filter(predicate=[type = "library"])
                └── Scan(collection="components")
```

#### Esempio e Risultato
```sql
FIND VULNERABLE LIBRARIES SEVERITY >= HIGH IN "tests/fixtures/sample_cyclonedx.json";
```
Output:
```
+------------+---------+---------+----------------+----------+-------+----------------------+
| name       | version | type    | vuln_id        | severity | score | description          |
+============+=========+=========+================+==========+=======+======================+
| log4j-core | 2.14.1  | library | CVE-2021-44228 | critical | 10.0  | Apache Log4j Core    |
| qs         | 6.7.0   | library | CVE-2022-29244 | high     | 7.5   | A querystring parser |
+------------+---------+---------+----------------+----------+-------+----------------------+
Total: 2 row(s) [Backend: Native CycloneDX Engine]
```

---

### Costrutto 3: `SHOW TREE [OF "<root>"] [DEPTH <n>];`

#### Problema Risolto
Permette di visualizzare visivamente la struttura dell'albero delle dipendenze per comprendere attraverso quali percorsi sono introdotte le librerie.

#### Sintassi e Semantica
- Sintassi: `SHOW (TREE | DEPENDENCIES) [OF "<component>"] [DEPTH <n>] [IN "<file.json>"];`
- Semantica: Esegue una BFS/DFS in direzione uscente (`FORWARD`) a partire dal nodo specificato fino alla profondità massima richiesta.

#### Abbassamento (Lowering) in IR
```
Project(columns=[name, version, depth, bom-ref])
  └── HashJoin(on left.ref == right.bom-ref)
        ├── Left Input:
        │     GraphTraverse(target="my-web-app", direction=FORWARD, max_depth=2)
        │       └── Scan(collection="dependencies")
        └── Right Input:
              Scan(collection="components")
```

#### Esempio con Output Formattato ad Albero (`--format tree`)
```sql
SHOW TREE OF "my-web-app" DEPTH 2;
```
Output:
```
Dependency Tree:
└── express@4.17.1
└── log4j-core@2.14.1
│   └── body-parser@1.19.0
```

---

### Costrutto 4: `FIND BLAST RADIUS OF "<cve-id>";`

#### Problema Risolto
Valuta l'impatto complessivo di una CVE sul sistema: calcola la frazione dell'intera base software compromessa e determina se l'applicazione primaria (`metadata.component`) o i servizi esterni sono raggiungibili e quindi esposti all'attacco.

#### Sintassi e Semantica
- Sintassi: `FIND BLAST RADIUS OF "<cve-id>" [IN "<file.json>"];`
- Semantica: Identifica i componenti bersaglio della vulnerabilità, esegue una chiusura transitiva inversa (`reverse reachability`), calcola la cardinalità dei nodi impattati e verifica l'intersezione con il nodo radice dell'applicazione.

#### Abbassamento (Lowering) in IR
```
BlastRadius(vulnerability_id="CVE-2021-44228")
  └── Scan(collection="vulnerabilities")
```

#### Esempio e Risultato
```sql
FIND BLAST RADIUS OF "CVE-2021-44228" IN "tests/fixtures/sample_cyclonedx.json";
```
Output:
```
+----------------------------------+-----------------------+
| Metric                           | Value                 |
+==================================+=======================+
| Vulnerability ID                 | CVE-2021-44228        |
| CVSS Severity                    | critical              |
| CVSS Score                       | 10.000000             |
| Total Components in SBOM         | 6                     |
| Directly Affected Components     | 1                     |
| Transitively Impacted Components | 2                     |
| Blast Radius (%)                 | 33.333333%            |
| Root Application Exposed?        | YES (CRITICAL IMPACT) |
+----------------------------------+-----------------------+
```

---

### Costrutto 5: Compilatore con Modalità `--explain` e Generazione di Comandi `sbom-utility`

#### Valore Accademico
Durante la discussione del progetto, è essenziale dimostrare alla commissione che il sistema è un **vero compilatore con analisi multi-stadio** e non un semplice script.

La modalità `--explain` isola e visualizza:
1. **Fase Lessicale**: Elenco formale dei token con coordinate posizionali (`line:column`);
2. **Fase Sintattica**: Struttura gerarchica dell'albero AST;
3. **Fase Semantica**: Esito della validazione rispetto allo schema catalog CycloneDX;
4. **Fase di Lowering**: Piano di esecuzione IR con operatori relazionali e grafi;
5. **Fase di Code Generation**: Traduzione automatica nel comando CLI `sbom-utility query ...` per le query supportate, oppure spiegazione analitica del motivo per cui la query richiede il motore nativo in memoria (presenza di join relazionali o grafi).
