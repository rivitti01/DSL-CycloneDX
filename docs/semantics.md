# Analisi Semantica e Type System (Semantics)

Questo documento definisce le regole semantiche, il modello dei dati e il type system implementati nella fase di **Semantic Analysis** del CycloneDX Query DSL.

---

## 1. Modello di Dominio CycloneDX e Simboli

Il compilatore include uno **Schema Catalog** a conoscenza delle specifiche CycloneDX (v1.2 – v1.6+). Le collezioni valide e i rispettivi campi sono formalizzati come segue:

### 1.1 Collezioni Valide
- `components`: Catalogo delle componenti software (librerie, framework, moduli, container).
- `vulnerabilities`: Catalogo delle vulnerabilità dichiarate (CycloneDX VEX/VDR).
- `dependencies`: Grafo delle dipendenze espresse come liste di adiacenza (`ref` $\rightarrow$ `dependsOn[]`).
- `metadata.component`: Descrizione del componente primario o applicazione radice.
- `services`: Servizi ed endpoint dichiarati nell'architettura.

Tentare di interrogare una collezione non registrata produce un errore semantico:
```
error: Unknown collection 'unknown_coll'. Valid collections are: components, vulnerabilities, dependencies, metadata.component, services
```

---

## 2. Type System

Il DSL implementa un sistema di tipi statico ma flessibile per validare espressioni e predicati prima dell'esecuzione:

| Tipo | Descrizione | Esempi |
| :--- | :--- | :--- |
| `String` | Testo alfanumerico | `"express"`, `'library'`, `"CVE-2021-44228"` |
| `Integer` | Numero intero | `10`, `502`, `1321` |
| `Float` | Numero decimale a virgola mobile | `7.5`, `9.8`, `10.0` |
| `Boolean` | Valore di verità | `true`, `false` |
| `Severity` | Livello di severità CVSS ordinato | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `NONE` |
| `Array` | Vettore di elementi | `dependencies[].dependsOn`, `vulnerabilities[].cwes` |
| `Object` | Struttura JSON annidata | `ratings[0]`, `supplier` |

### 2.1 Regole di Inferenza di Tipo delle Espressioni
1. **Letterali**: Il tipo corrisponde al valore del token (`String`, `Integer`, `Float`, `Boolean`, `Severity`).
2. **Riferimenti a colonna (`ColumnRefExpr`)**:
   - `ratings.severity`, `severity`, `cvss-severity` $\rightarrow$ `Severity`
   - `ratings.score`, `score` $\rightarrow$ `Float`
   - `cwe` $\rightarrow$ `Integer`
   - `name`, `version`, `type`, `bom-ref`, `purl`, `description`, `id` $\rightarrow$ `String`
3. **Operatori Unari**:
   - `NOT <expr>`: richiede che `<expr>` sia di tipo `Boolean` e produce `Boolean`.
4. **Operatori Binari**:
   - Qualsiasi operatore di confronto (`=`, `!=`, `<`, `<=`, `>`, `>=`, `CONTAINS`, `MATCHES`, `LIKE`) produce un risultato di tipo `Boolean`.
   - Gli operatori logici (`AND`, `OR`) richiedono che entrambi gli operandi siano di tipo `Boolean` e producono `Boolean`.

---

## 3. Matrice di Compatibilità degli Operatori

| Operatore | Operando Sinistro | Operando Destro | Validità | Note |
| :--- | :--- | :--- | :--- | :--- |
| `=`, `!=` | `T` | `T` | **Valido** | Uguaglianza per tipi identici |
| `=`, `!=` | `Integer` | `Float` | **Valido** | Promozione numerica implicita |
| `<`, `<=`, `>`, `>=` | `Numeric` | `Numeric` | **Valido** | Confronto d'ordine numerico |
| `<`, `<=`, `>`, `>=` | `Severity` | `Severity` | **Valido** | Ordinamento CVSS (`NONE` < `INFO` < `LOW` < `MEDIUM` < `HIGH` < `CRITICAL`) |
| `<`, `<=`, `>`, `>=` | `String` | `Numeric` | **Errore Semantico** | Incompatibilità di tipo |
| `AND`, `OR` | `Boolean` | `Boolean` | **Valido** | Connettivi logici |
| `AND`, `OR` | `String` | `Boolean` | **Errore Semantico** | Operando sinistro non booleano |
| `CONTAINS` | `String` | `String` | **Valido** | Sottostringa case-sensitive o insensitive |
| `MATCHES`, `LIKE` | `String` | `String` (Regex) | **Valido** | Corrispondenza regex ECMAScript/POSIX |

---

## 4. Vincoli Semantici delle Istruzioni

### 4.1 Clausola `LIMIT`
- Il valore associato a `LIMIT` deve essere un intero strettamente positivo ($> 0$). Un valore nullo o negativo solleva un errore semantico immediato:
  ```
  error: LIMIT must be greater than 0
  ```

### 4.2 Parametro `DEPTH` (`SHOW TREE`)
- Il valore di profondità massima deve essere un intero positivo ($> 0$):
  ```
  error: DEPTH must be greater than 0
  ```

### 4.3 Bersaglio `WHO USES` e `FIND BLAST RADIUS`
- L'identificatore del componente o la CVE non possono essere stringhe vuote.
