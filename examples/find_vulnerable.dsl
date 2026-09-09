-- Esempio 3: Vulnerability Correlation & Relational Join
-- Trova tutte le librerie affette da vulnerabilità con severità HIGH o CRITICAL
FIND VULNERABLE LIBRARIES
SEVERITY >= HIGH
IN "tests/fixtures/sample_cyclonedx.json";
