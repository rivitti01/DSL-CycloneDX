# Fase 0: Analisi di CycloneDX e `sbom-utility`

Questo documento riporta i risultati dell'indagine preliminare condotta sulle specifiche CycloneDX e sul tool ufficiale [`sbom-utility`](https://github.com/CycloneDX/sbom-utility), in preparazione alla progettazione del Domain Specific Language (DSL) per il corso di **Formal Languages and Compilers** (Politecnico di Milano).

---

## 1. Cos'è e cosa fa `sbom-utility`

`sbom-utility` è un'applicazione da riga di comando open source sviluppata all'interno del progetto OWASP CycloneDX (scritta in Go). Il suo obiettivo è validare, analizzare, interrogare e modificare Software Bill of Materials (SBOM) in formato CycloneDX e SPDX.

### Comandi principali offerti dal tool:
1. **`validate`**: Valida SBOM (CycloneDX o SPDX) a fronte dei rispettivi JSON schema ufficiali e di eventuali custom schema o regole aziendali.
2. **`query`**: Esegue interrogazioni "SQL-like" sul modello a oggetti JSON del documento SBOM tramite i flag `--from`, `--select`, `--where`.
3. **`component list`**: Estrae l'elenco dei componenti dichiarati nel documento (`metadata.component` e array `components`), con supporto per formati di output tabulari (`txt`, `csv`, `md`).
4. **`vulnerability list`**: Elenca le vulnerabilità dichiarate (array `vulnerabilities` per CycloneDX VEX/VDR) con severità CVSS, CWE, stato di analisi ed entità affette.
5. **`license list` / `license policy`**: Estrae le licenze dichiarate e ne valuta la conformità rispetto a policy configurate in un file `license.json`.
6. **`resource list`**: Elenca componenti e servizi.
7. **`trim`, `patch`, `diff`**: Funzionalità di modifica del documento (riduzione di campi, applicazione di RFC 6902 JSON patch, calcolo delta tra SBOM).

### Come funziona il comando `query` in `sbom-utility`:
- `--from <dot.path>`: Dereferenzia un percorso puntato nel documento JSON (ad esempio `metadata.component`, `components`, `vulnerabilities`, `dependencies`).
- `--select <k1,k2,...>`: Proietta una lista di chiavi di primo livello dell'oggetto o degli elementi dell'array (oppure `*` per tutte).
- `--where <k1=regex,k2=regex>`: Filtra gli elementi di un array imponendo corrispondenze regex (con operazione di `AND` implicito) sulle proprietà di primo livello.
- **Output**: Il comando `query` supporta esclusivamente output in formato JSON.

---

## 2. Come sono rappresentate le informazioni in CycloneDX

Le SBOM CycloneDX (dalla v1.2 alla v1.6+) strutturano i dati software attraverso sezioni chiave:

1. **Root Component (`metadata.component`)**:
   Rappresenta l'applicazione principale (nome, versione, tipo `application`, `bom-ref`).
2. **Componenti (`components[]`)**:
   Inventario delle librerie, framework, moduli, container o file.
   - Ogni componente possiede un identificativo univoco: `bom-ref` (spesso formato Package URL - `purl`, es. `pkg:npm/express@4.17.1`).
   - Contiene attributi: `name`, `version`, `type` (`library`, `framework`, `application`), `description`, `licenses[]`, `hashes[]`, `supplier`, `purl`.
3. **Grafo delle Dipendenze (`dependencies[]`)**:
   Rappresenta le relazioni di dipendenza diretta tra componenti:
   ```json
   "dependencies": [
     {
       "ref": "pkg:npm/my-app@1.0.0",
       "dependsOn": [
         "pkg:npm/express@4.17.1",
         "pkg:npm/lodash@4.17.21"
       ]
     },
     {
       "ref": "pkg:npm/express@4.17.1",
       "dependsOn": [
         "pkg:npm/qs@6.7.0"
       ]
     }
   ]
   ```
   Se $A$ include $B$ in `dependsOn`, $A$ dipende direttamente da $B$. Se $B$ dipende da $C$, $A$ dipende da $C$ in modo transitivo.
4. **Vulnerabilità (`vulnerabilities[]`)**:
   Rappresenta CVE o advisory di sicurezza noti (CycloneDX 1.4+ VEX/VDR):
   - `id`: identificativo univoco (es. `CVE-2021-44228`).
   - `ratings[]`: severità (`critical`, `high`, `medium`, `low`) e score CVSS numerico.
   - `affects[]`: lista di oggetti `{"ref": "<bom-ref>"}`, che collegano la vulnerabilità ai componenti affetti tramite il loro `bom-ref`.

---

## 3. Limitazioni critiche di `sbom-utility`

Dall'analisi del codice sorgente Go di `sbom-utility` emergono limitazioni fondamentali rispetto a ciò che ci si aspetterebbe da un linguaggio di interrogazione completo per la sicurezza del software:

1. **Assenza totale di supporto per Join / Correlazioni relazionali**:
   `sbom-utility` opera solo su una singola collezione per volta. Non è possibile correlare `vulnerabilities` con `components`: ad esempio, non può rispondere alla domanda *"Mostra nome, versione e licenza dei componenti con vulnerabilità Critical"*.
2. **Nessun supporto per l'analisi del Grafo delle Dipendenze**:
   Non esiste alcun comando per calcolare:
   - Dipendenze transitive (chiusura transitiva).
   - Dipendenze inverse (*"Chi usa questa libreria?"* / reverse lookup).
   - Cammini di dipendenza (*"Quale catena porta l'applicazione a importare la libreria X?"*).
   Interrogare `--from dependencies` restituisce semplicemente la lista statica di adiacenze serializzata nel JSON.
3. **Predicati di filtro (`--where`) estremamente primitivi**:
   - Accetta solo uguaglianze regex `campo=regex`.
   - Nessun supporto per `OR`, `NOT`, espressioni booleane annidate o parentesi.
   - Nessun confronto numerico (es. `score >= 7.5`).
   - Nessuna navigazione su campi annidati (es. `ratings[0].severity`).
4. **Assenza di proiezioni avanzate e aggregazioni**:
   Nessun supporto per `COUNT`, `DISTINCT`, alias (`AS`), o campi calcolati.
5. **Overhead di esecuzione da C++**:
   Invocare `sbom-utility` per ogni operazione richiede la generazione di processi esterni (`fork`/`exec`), parsing di stream JSON da pipe e dipendenza dall'installazione del binario Go sul sistema.

---

## 4. Decisione Architetturale: Strategia Ibrida / Dual Engine

In linea con le indicazioni del docente (*"ad esempio generando comandi sbom-utility... valutare una strategia ibrida in cui il DSL utilizza direttamente la struttura CycloneDX"*), la soluzione architetturale ideale comprende:

1. **Generatore di Comandi `sbom-utility` (Target CLI)**:
   - Il compilatore sa mappare le query base compatibili nei rispettivi comandi `sbom-utility query` e `sbom-utility component list`.
   - Con il flag `--explain` o `--target=sbom-utility`, il compilatore mostra e può invocare i comandi nativi del tool.
2. **Engine CycloneDX Nativo in C++ (Target In-Memory)**:
   - Un motore C++ moderno basato su AST/IR, che analizza direttamente il documento CycloneDX (usando ad esempio `nlohmann/json`).
   - Costruisce indici veloci in memoria: mappa hash dei `bom-ref`, grafo diretto e inverso delle dipendenze, indice `affects -> component`.
   - Esegue join, chiusure transitive, algoritmi di cammino minimo e predicati complessi (`AND`, `OR`, `NOT`, confronti numerici).
3. **Query Lowering formale**:
   - I costrutti avanzati di sicurezza del DSL vengono trasformati in costrutti IR di base (scansioni, filtri, join relazionali, chiusure di grafi).
   - Questo garantisce sia il rigore teorico richiesto dal corso di Compilatori, sia la massima utilità pratica nell'indagine sulla supply chain software.

---

## 5. Quali funzionalità useremo ed esporremo nel DSL

### Funzionalità esposte dal DSL:
- **Query Base SQL-like**:
  - `SELECT <campi>` con supporto a campi specifici o `*`.
  - `FROM <collezione>` (`components`, `vulnerabilities`, `dependencies`, `metadata.component`).
  - `WHERE <espressione>` con operatori `=`, `!=`, `<`, `<=`, `>`, `>=`, `LIKE`, `MATCHES`, `CONTAINS`, combinabili con `AND`, `OR`, `NOT` e parentesi.
  - `ORDER BY <campo> [ASC | DESC]`.
  - `LIMIT <n>`.
- **Costrutti di Dominio Avanzati (Security & Supply Chain)**:
  - `WHO USES "<component-name>" [TRANSITIVE | DIRECT];`
  - `FIND VULNERABLE (COMPONENTS | LIBRARIES) [SEVERITY >= <level>] [WHERE ...];`
  - `SHOW DEPENDENCY PATH FROM "<source>" TO "<target>";`
  - `SHOW TREE [OF "<component>"] [DEPTH <n>];`
  - `FIND IMPACT OF VULNERABILITY "<cve-id>";`
  - `AUDIT LICENSES [ALLOWING (...) | REJECTING (...)];`

### Funzionalità lasciate fuori e motivazione:
- **Comandi di modifica (`patch`, `trim`)**: Il nostro progetto è un linguaggio di interrogazione e analisi (Query Language), non uno strumento di mutazione o patching di file JSON.
- **Validazione con schema personalizzati (`validate --custom`)**: La validazione formale dell'input SBOM può essere eseguita a monte (o delegata direttamente al tool), ma non appartiene al dominio di un linguaggio di query.
- **Supporto per formati diversi da CycloneDX JSON**: `sbom-utility query` supporta solo CycloneDX JSON (rifiuta SPDX o XML per le query). Mantenere il focus su CycloneDX JSON standard (v1.2–v1.6+) assicura la massima profondità semantica senza disperdere sforzi su parsing di formati eterogenei.
