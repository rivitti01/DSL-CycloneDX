// ==============================================================================
// DEMO SCENARIO: Security Audit on Cloud-Native Node.js Payment Microservice
// Target SBOM: tests/fixtures/payment_service_node_cyclonedx.json
// ==============================================================================

// --- STEP 1: Inventory Overview (SQL-like Group By & Aggregation) ---
// How many software components does this service use, grouped by type?
SELECT type, COUNT(*)
FROM components
IN "tests/fixtures/payment_service_node_cyclonedx.json"
GROUP BY type;

// --- STEP 2: Security Assessment (SQL-like Filtering & Aggregation) ---
// Distribution of declared vulnerabilities with CVSS score >= 7.0
SELECT severity, COUNT(*)
FROM vulnerabilities
IN "tests/fixtures/payment_service_node_cyclonedx.json"
WHERE score >= 7.0
GROUP BY severity
ORDER BY severity ASC;

// --- STEP 3: Relational Vulnerability Join (High-level Security Construct) ---
// Find libraries affected by HIGH or CRITICAL advisories via in-memory HashJoin
FIND VULNERABLE LIBRARIES SEVERITY >= HIGH
IN "tests/fixtures/payment_service_node_cyclonedx.json";

// --- STEP 4: Upstream Supply Chain Analysis (Reverse Graph BFS) ---
// Who is importing the vulnerable "qs" parser? Direct or transitive dependency?
WHO USES "qs" TRANSITIVE
IN "tests/fixtures/payment_service_node_cyclonedx.json";

// --- STEP 5: Blast Radius Impact Calculation ---
// Compute supply chain exposure for Critical RCE flaw CVE-2022-23529
FIND BLAST RADIUS OF "CVE-2022-23529"
IN "tests/fixtures/payment_service_node_cyclonedx.json";

// --- STEP 6: CI/CD DevSecOps Compliance Gate ---
// Block build if any CRITICAL vulnerability affects our production dependencies
ASSERT NO VULNERABILITIES SEVERITY >= CRITICAL
IN "tests/fixtures/payment_service_node_cyclonedx.json";
