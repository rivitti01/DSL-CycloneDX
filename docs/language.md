# Manuale di Riferimento del Linguaggio (DSL Reference)

Il **CycloneDX Query DSL** è un linguaggio orientato al dominio ideato per consentire a sviluppatori, analisti di sicurezza e responsabili della supply chain di interrogare, filtrare e analizzare Software Bill of Materials (SBOM) nel formato standard CycloneDX.

---

## 1. Struttura Generale delle Query

Ogni istruzione termina con un punto e virgola `;`. Più istruzioni possono essere scritte in sequenza nello stesso script o sessione interattiva.

È possibile inserire commenti:
```sql
-- Commento stile SQL a riga singola
// Commento stile C++ a riga singola
/* Commento
   multiriga */
```

Il file SBOM da interrogare può essere specificato:
1. All'interno della query tramite la clausola `IN "percorso/file.json"`;
2. Da riga di comando tramite l'opzione `-b percorso/file.json`;
3. Nella sessione interattiva tramite il comando `:bom percorso/file.json`.

---

## 2. Query Base SQL-like (`SELECT`)

### 2.1 Sintassi
```sql
SELECT <proiezioni>
FROM <collezione>
[IN "<file_sbom.json>"]
[WHERE <condizione>]
[ORDER BY <campo> [ASC | DESC]]
[LIMIT <numero>];
```

### 2.2 Collezioni Supportate (`FROM`)
- `components`: Elenco dei componenti software (librerie, framework, moduli).
- `vulnerabilities`: Catalogo delle vulnerabilità dichiarate (CycloneDX VEX/VDR).
- `dependencies`: Grafo delle dipendenze dirette (`ref` e `dependsOn`).
- `metadata.component`: Informazioni sull'applicazione o sistema radice.

### 2.3 Proiezioni
- `SELECT *` seleziona tutti i campi disponibili.
- `SELECT campo1, campo2, ...` seleziona solo i campi specificati (es. `name, version, type, purl`).

### 2.4 Condizioni di Filtro (`WHERE`)
Supporta espressioni logiche e relazionali complete:
- **Uguaglianza e disuguaglianza**: `=`, `!=`
- **Confronti numerici / ordinamento**: `<`, `<=`, `>`, `>=`
- **Operatori logici**: `AND`, `OR`, `NOT`, con parentesi tonde `( ... )`
- **Operatori di stringa**:
  - `CONTAINS`: verifica se la stringa contiene una sottostringa (es. `name CONTAINS 'log4j'`).
  - `MATCHES` o `LIKE`: corrispondenza tramite espressione regolare (es. `version MATCHES '^2\..*'`).

### 2.5 Esempi
```sql
-- Tutte le librerie ordinate per nome
SELECT name, version, purl
FROM components
WHERE type = 'library'
ORDER BY name ASC
LIMIT 10;

-- Vulnerabilità con score CVSS elevato
SELECT id, cvss-severity, score
FROM vulnerabilities
WHERE score >= 7.5 AND (severity = CRITICAL OR severity = HIGH);
```

---

## 3. Costrutti Avanzati di Sicurezza

### 3.1 `WHO USES` (Reverse Dependency Lookup)
Risponde alla domanda fondamentale: *"Chi nel mio progetto sta usando questa specifica libreria?"*.

```sql
WHO USES "<component-identifier>" [TRANSITIVE | DIRECT] [IN "<file.json>"];
```
- Se omesso, il comportamento predefinito è `TRANSITIVE` (esplora l'intera catena di dipendenze fino alla radice).
- Se specificato `DIRECT`, considera solo chi ha dichiarato la dipendenza diretta immediata.

**Esempio:**
```sql
WHO USES "log4j-core" TRANSITIVE;
```

---

### 3.2 `FIND VULNERABLE` (Correlazione Vulnerabilità-Componenti)
Esegue un join relazionale automatico tra il catalogo delle vulnerabilità e i componenti, correlando gli attributi software con gli advisory di sicurezza.

```sql
FIND VULNERABLE (COMPONENTS | LIBRARIES)
[SEVERITY [= | != | < | <= | > | >=] <livello>]
[WHERE <condizione_aggiuntiva>]
[IN "<file.json>"];
```
- `COMPONENTS`: considera tutti i componenti (applicazioni, container, librerie, moduli).
- `LIBRARIES`: restringe l'analisi alle sole librerie di terze parti.
- `SEVERITY`: filtro sulla severità CVSS (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `NONE`).

**Esempi:**
```sql
-- Trova librerie con vulnerabilità ad alta gravità
FIND VULNERABLE LIBRARIES SEVERITY >= HIGH;

-- Trova vulnerabilità con CWE specifico
FIND VULNERABLE COMPONENTS WHERE cwe = 502;
```

---

### 3.3 `SHOW TREE` (Visualizzazione Albero delle Dipendenze)
Ricostruisce la gerarchia delle dipendenze dirette e transitive.

```sql
SHOW (TREE | DEPENDENCIES) [OF "<component-name>"] [DEPTH <n>] [IN "<file.json>"];
```
- `OF "<component>"`: seleziona il nodo radice dell'albero (se omesso, usa l'applicazione definita in `metadata.component`).
- `DEPTH <n>`: limita la profondità massima dell'albero di dipendenze.

**Esempio:**
```sql
SHOW TREE OF "my-web-app" DEPTH 3;
```

---

### 3.4 `FIND BLAST RADIUS` (Analisi del Raggio d'Impatto)
Calcola l'esposizione globale del sistema rispetto a una vulnerabilità nota (CVE).

```sql
FIND BLAST RADIUS OF "<cve-id>" [IN "<file.json>"];
```
Restituisce un report sintetico con:
- CVSS Score e gravità dell'advisory;
- Componenti direttamente affetti;
- Componenti transitivamente impattati;
- Percentuale di compromissione della supply chain (`Blast Radius %`);
- Verifica se l'applicazione principale di primo livello è direttamente o transitivamente esposta.

**Esempio:**
```sql
FIND BLAST RADIUS OF "CVE-2021-44228";
```

---

## 4. Modalità di Esecuzione e Formattazione

### 4.1 Formati di Output (`-f`, `--format`)
1. **Tabella ASCII (`table`)**: Formato predefinito con colonne allineate, statistiche di riga e tempo di esecuzione.
2. **JSON (`json`)**: Output standard JSON per pipeline CI/CD o integrazione con altri script.
3. **Albero (`tree`)**: Visualizzazione gerarchica con caratteri ad albero (`├──`, `└──`) particolarmente indicata per `SHOW TREE`.

### 4.2 Modalità Spiegazione (`--explain`)
Aggiungendo `--explain` alla riga di comando (o `:explain on` nella REPL), il compilatore mostra in dettaglio:
1. Token generati dal Lexer con coordinate `linea:colonna`;
2. Albero sintattico astratto (`AST`);
3. Esito dell'analisi semantica e validazione tipi;
4. Piano di esecuzione abbassato (`IR Execution Plan`);
5. Mapping ed eventuale comando `sbom-utility` sintetizzato.
