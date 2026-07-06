# CodeQL Query Synthesis Prompt Template

```
You are an expert CodeQL query writer specializing in C and C++ security vulnerabilities.

PLEASE THINK CAREFULLY AND THOROUGHLY BEFORE OUTPUTTING A QUERY.

## Your Goal
Synthesize a CodeQL query for C/C++ that satisfies ALL THREE of these conditions:
1. WELL-FORMED: The query compiles without errors using CodeQL for C/C++ version 2.25.3
2. VULNERABILITY DETECTION: The query returns >= 1 result on the VULNERABLE (pre-patch) version of the code
3. FIX DISCRIMINATION: The query returns 0 results on the FIXED (post-patch) version of the code

A query is only SUCCESSFUL when ALL THREE conditions hold.

## What I Am Giving You

### ARVO/OSS-FUZZ Task ID / CVE
[ARVO_TASK_ID]

### Project Name and GitHub Repo
[PROJECT_NAME]: [PROJECT_REPO_URL]

### Vulnerability Type (CWE)
[CWE_ID]: [CWE_NAME] / [ONE_LINE_DESCRIPTION_OF_ROOT_CAUSE]

### Vulnerability Description
[DETAILED_DESCRIPTION: which function(s) are involved, what triggers the bug,
what state becomes invalid or corrupt, and what the runtime crash or sanitizer
report looks like at a high level]

### Crash Info (from error.txt)
[SANITIZER_NAME]: [CRASH_TYPE]
Call stack: [FUNCTION_A] ([FILE]:LINE) -> [FUNCTION_B] ([FILE]:LINE) -> ...
Runtime error: [EXACT_RUNTIME_ERROR_MESSAGE_OR_SANITIZER_OUTPUT]

### Patch Diff
REMOVED (vulnerable) — [WHERE IN THE CODE THIS APPEARED, e.g.,
"inside function X at the Y case of switch Z"]:

[VULNERABLE_CODE_SNIPPET]

ADDED (fixed) — [DESCRIPTION OF WHAT REPLACED IT]:

[FIXED_CODE_SNIPPET]

THE FIX: [EXPLANATION of what invariant was violated, what the vulnerable code
omitted or did incorrectly, and why the fix restores correct behavior]

### Baseline CodeQL Query (Standard Query for This CWE)
[PASTE_FULL_BASELINE_CODEQL_QUERY_HERE]

## How to Approach This — Follow These Steps

### Step 1: Understand the Patch
Read the patch diff carefully.
- What did the developer ADD (+ lines)? This is the FIX.
- The fix is almost always a bounds check, a size validation, an integer
  overflow check, or a NULL check that was MISSING.
- That missing check = the vulnerability pattern.
- That added check = your SANITIZER predicate.

### Step 2: Identify the Vulnerable Pattern
Ask yourself:
- WHERE does the bad data come from? (SOURCE)
  In C/C++: external input via read(), fread(), recv(),
  user-supplied size parameters, file parsing functions
- WHERE does the bug happen? (SINK)
  In C/C++: memcpy(), malloc() with arithmetic, array indexing,
  strcpy(), sprintf() without bounds
- WHAT connects them? (TAINT FLOW)
  How does the data travel from the source to the dangerous op?
- WHAT does the fix add? (SANITIZER/BARRIER)
  Usually: an if() check, a ternary min/max, an assertion, or a
  size comparison that now guards the dangerous operation

### Step 3: Understand the Baseline Query's Weakness
Look at the standard CodeQL query you were given.
- What does it currently find?
- What is it MISSING that would catch this specific vulnerability?

[EXPLANATION OF WHY THE BASELINE MISSES THIS BUG: describe the structural
reason the standard query cannot model this pattern. Choose the framing
that fits — examples:
- it only tracks truly uninitialized locals, but the variable here is
  initialized with a semantically dangerous value
- it only models pointer arithmetic past allocation bounds, but the bug is
  a wrong function dispatch leaving a struct slot unpopulated
- it only works on statically-known sizes, but the overflow size here is
  determined at runtime by the relationship between two or more variables]

- [BULLET: what the baseline DOES model]
- [BULLET: what structural pattern it CANNOT model, and why]

- Your job is to detect [CONCISE DESCRIPTION OF THE SPECIFIC STRUCTURAL
  PATTERN TO TARGET, derived from the patch diff].

### Step 4: Write the Improved Query
Build on top of the baseline query. Do NOT start from scratch.
Add one or more of:
a) More specific SOURCE classes matching this project's input functions
b) More specific SINK classes matching this project's dangerous operations
c) A SANITIZER/BARRIER predicate matching exactly what the patch added —
   derive this from the diff, not from assumptions. The sanitizer must match
   the fixed code and NOT match the vulnerable code.
d) Additional taint steps if data flows through structs, function pointers,
   or intermediate variables

### Step 5: Quality Check Before Outputting
Before writing the final query, verify:
- Is the import `import cpp` (NOT `import java`)?
- Are all predicate names real? (semmle.code.cpp.*)
- Is the sanitizer predicate tight enough to only match the fixed code
  pattern, not the vulnerable code?
- Will this compile with CodeQL 2.25.3?

## What You Must Add
[2–4 sentences restating why the baseline misses this bug, focusing on the
structural gap between what the baseline models and what this vulnerability
actually is]

Your enhancement must:
1. Identify the SINK from the crash info and patch diff — find the dangerous
   operation or call site in the vulnerable file and function
2. Identify the SOURCE of the unsafe value — trace which variable controls
   the dangerous operation and where its value originates
3. Derive the SANITIZER from the patch diff — identify what comparison, guard,
   clamping expression, or structural change was ADDED in the fixed code.
   That added pattern is your barrier. The query must NOT fire when that
   pattern is present.
4. Write a predicate that detects the dangerous pattern existing WITHOUT the
   sanitizer present. The query fires on vulnerable code and goes silent on
   fixed code.

## Output Format
Output ONLY the CodeQL query. No explanation, no markdown fences.
Start with the /** @name ... */ documentation block.
Use @kind problem unless taint tracking is needed.

## CodeQL C/C++ Quick Reference
- Import: `import cpp` (NOT import java)
- Function calls: FunctionCall, .getTarget().getName()
- Enclosing function: .getEnclosingFunction()
- Source file: .getFile().getBaseName()
- If-statements: IfStmt, .getCondition(), .getThen(), .getElse()
- Struct/field access: FieldAccess, .getTarget().getName()
- Ancestor statement traversal: getParent*()
- Find calls in same function: getEnclosingFunction()
- Pointer dereference: PointerDereferenceExpr
- Taint tracking: import semmle.code.cpp.dataflow.TaintTracking
- Common dangerous functions: memcpy, strcpy, malloc — check via
  FunctionCall and .getTarget().getName()
- Size arguments: fc.getArgument(2) for memcpy size
- Variable names: va.getTarget().getName()
- Equality comparisons to zero: EQExpr, check operands for
  VariableAccess and zero literal
- Barriers: check enclosing function for a guarding pattern

## Success Criteria
SUCCESS = vulnerable version results >= 1 AND fixed version results = 0
FAILURE = fixed version has any results (false positive)
FAILURE = vulnerable version has 0 results (missed the bug)
```
