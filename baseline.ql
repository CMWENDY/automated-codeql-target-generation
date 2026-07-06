// =============================================================================
// baseline.ql
// =============================================================================
//
// PURPOSE:
//   This file holds the STANDARD (unmodified) CodeQL query for the CWE class
//   of the vulnerability you are targeting. It serves as the starting point
//   that the LLM-synthesized enhanced query is built on top of.
//
// HOW TO USE:
//   1. Look up the CWE ID for your vulnerability (e.g., CWE-125, CWE-476,
//      CWE-457). This is provided in the SAILOR vulnerability spec.
//   2. Find the corresponding standard CodeQL query for that CWE. These can
//      be found in the CodeQL query packs:
//        - GitHub: https://github.com/github/codeql
//        - Path:   codeql/cpp/ql/src/Security/CWE/CWE-<ID>/
//   3. Copy and paste the FULL contents of that standard query below,
//      replacing this comment block.
//   4. Do NOT modify the query. This file should remain the unedited
//      baseline so that baseline vs. enhanced results can be compared.
//
// ROLE IN THE PIPELINE:
//   - Run against the VULNERABLE version of the target project.
//     Expected: 0 results (the baseline misses the bug — this is expected
//     and is exactly why the enhanced query is needed).
//   - Run against the FIXED version of the target project.
//     Expected: 0 results (no false positives on patched code).
//   - Results are compared against enhanced.ql to measure the detection
//     gain from LLM-synthesized query generation.
//
// =============================================================================
// PASTE THE BASELINE CWE QUERY BELOW THIS LINE
// =============================================================================
