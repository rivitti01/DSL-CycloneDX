-- Esempio 2: Reverse Dependency Lookup
-- Scopre tutte le componenti che dipendono (anche transitivamente) dalla libreria 'qs'
WHO USES "qs" TRANSITIVE IN "tests/fixtures/sample_cyclonedx.json";
