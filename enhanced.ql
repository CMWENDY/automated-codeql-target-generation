// =============================================================================
// enhanced.ql
// =============================================================================
//
// PURPOSE:
//   This file holds the LLM-SYNTHESIZED CodeQL query for a specific
//   vulnerability. It is derived from the baseline CWE query but extended
//   to detect the exact vulnerable pattern that the baseline misses — and
//   to go silent on the fixed version of the code.
//
// HOW TO USE:
//   1. Fill out the vulnerability spec fields in the prompt template.
//      Required fields come from CyberGym:
//        - ARVO/OSS-Fuzz Task ID or CVE
//        - Project name and repo URL
//        - CWE ID and root cause description
//        - Vulnerability description
//        - Crash info (sanitizer output and call stack)
//        - Patch diff (vulnerable snippet and fixed snippet, with explanation)
//        - Baseline query (copy from baseline.ql)
//   2. Submit the completed prompt to the LLM.
//   3. Copy and paste the LLM's output query below, replacing this comment
//      block. The LLM outputs ONLY the query — no explanation or markdown.
//   4. Verify the query header uses @kind problem (or @kind path-problem
//      if taint tracking is needed) and imports `import cpp` (NOT java).
//
// SUCCESS CRITERIA (ALL THREE must hold):
//   - WELL-FORMED:          Query compiles under CodeQL for C/C++ v2.25.3
//   - VULNERABILITY DETECTION: Returns >= 1 result on the VULNERABLE version
//   - FIX DISCRIMINATION:   Returns 0 results on the FIXED version
//
// ROLE IN THE PIPELINE:
//   - Run against the VULNERABLE version of the target project.
//     Expected: >= 1 result (the query catches the bug).
//   - Run against the FIXED version of the target project.
//     Expected: 0 results (the sanitizer predicate correctly blocks the
//     fixed code pattern, producing no false positives).
//   - Results are compared against baseline.ql to confirm detection gain.
//
// =============================================================================
// PASTE THE LLM-SYNTHESIZED QUERY BELOW THIS LINE
// =============================================================================
