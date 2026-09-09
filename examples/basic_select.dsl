-- Esempio 1: Query Base SQL-like su componenti
-- Mostra nome, versione e purl di tutte le librerie
SELECT name, version, purl
FROM components
IN "tests/fixtures/sample_cyclonedx.json"
WHERE type = 'library'
ORDER BY name ASC;
