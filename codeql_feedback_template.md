# CodeQL Query Feedback Prompt Template

```
YOU ARE AN EXPERT AT CREATING CODEQL QUERIES.

The previous CodeQL query did not succeed.

THINK CAREFULLY AND THOROUGHLY PLEASE!!! Here are the results:

Vulnerable version result count: [VULNERABLE_RESULT_COUNT]
Fixed version result count: [FIXED_RESULT_COUNT]

Previous query (iteration [ITERATION_NUMBER]):

[PASTE_PREVIOUS_QUERY_HERE]

Original patch diff for reference:

REMOVED (vulnerable):

[VULNERABLE_CODE_SNIPPET]

ADDED (fixed):

[FIXED_CODE_SNIPPET]

THE FIX: [EXPLANATION of what invariant was violated, what the vulnerable code
omitted or did incorrectly, and why the fix restores correct behavior]

## Diagnosis

### CASE A: Vulnerable version = 0 results (missed the bug)
The query is not finding the vulnerability. Debug in this order:
1. FUNCTION/FILE NAME MISMATCH
   - Is the dangerous function name spelled exactly right?
   - Is the filename check matching the right file?
   - Try removing the filename check entirely to see if that
     is what is blocking the result
2. SINK IS WRONG
   - Is the argument index correct for the dangerous operation?
   - memcpy size = argument index 2
   - malloc size = argument index 0
   - Look at the crash stack to find the exact function and line
3. SOURCE IS TOO NARROW
   - Is the variable name check matching the right variable?
   - Try broadening: remove one constraint at a time until results
     appear, then add constraints back one at a time
4. MISSING TAINT STEPS
   - Does the unsafe value flow through intermediate variables
     before reaching the sink?
   - Add getAChild*() traversal to catch sub-expressions

### CASE B: Fixed version still has results (false positive)
The sanitizer is not working. Debug in this order:
1. SANITIZER PREDICATE IS WRONG
   - Look at the + lines in the patch diff again
   - Does your sanitizer match exactly what was added?
   - Common mistake: checking the wrong variable name, or the
     wrong position of the check relative to the sink
2. SANITIZER IS IN THE WRONG POSITION
   - The fix may reorder statements rather than add a new check
   - In the fixed code, does the guarding computation happen
     BEFORE the dangerous operation?
   - Your sanitizer must reflect that ordering
3. SANITIZER CONDITION IS TOO LOOSE
   - If the sanitizer matches too broadly it fires on both versions
   - Tighten it: check the specific variable name, the specific
     expression pattern, or the specific argument being used

### CASE C: Both versions have the same non-zero results
The sanitizer is doing nothing at all. Completely rewrite it.
The barrier predicate is not actually blocking any results.
Check: is the sanitizer connected to the right query variable?

## Instructions
- Determine which CASE above applies based on the result counts,
  then apply the corresponding diagnosis
- If iteration number is < 3: apply EXACTLY ONE targeted fix
  based on the diagnosis above — do not change multiple things
  at once
- If iteration number is >= 3: you have COMPLETE AUTONOMY to
  redesign the query from scratch — abandon the previous approach
  entirely if needed, try a structurally different detection
  strategy, change the sink, source, sanitizer, or query kind
  (@kind problem vs @kind path-problem) as you see fit
- Output ONLY the corrected CodeQL query, no explanation
- Same output format rules as before: no markdown fences,
  start with the /** @name ... */ block

PLEASE PROVIDE THE CORRECTED QUERY PLEASE
```
