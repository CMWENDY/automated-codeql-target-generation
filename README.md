# Automated Target Generation for Vulnerability Detection

A patch-guided prompt and validation loop that gets an LLM to write bug-specific CodeQL queries for C/C++ code. Standard CodeQL query packs are written for broad coverage — one query per vulnerability class, across many codebases — and that generality has a real cost: on three confirmed, patched vulnerabilities in real projects, the baseline queries found nothing. This project closes that gap by synthesizing a query for the *specific* pattern each patch fixed, rather than relying on a generic class-wide rule.

Built as part of my work at the UCSB Verification Lab (advised by Prof. Tevfik Bultan), feeding into a larger 5-stage vulnerability detection pipeline described in "Bug Composition: Triggering Multiple Bugs with Agentic Driver Generation" (AgenticDev 2026, ASE 2026 Workshop Proceedings).

## The problem

Baseline CodeQL queries for a CWE class are written for broad coverage across many codebases, which means they miss project-specific variations of the pattern they're supposed to catch. Tested against three confirmed, patched vulnerabilities from the [CyberGym](https://github.com/sunblaze-ucb/cybergym) benchmark, the standard query packs found **0 of 3** — even though every bug had a public patch and a reproducible crash.

## Constraints

Accepted queries feed a downstream triage stage, so they have to be trustworthy, not just plausible. A query only counts as a success if it satisfies **all three** conditions:

1. **Well-formed** — compiles without errors under CodeQL for C/C++ 2.25.3
2. **Vulnerability detection** — returns ≥ 1 result on the vulnerable (pre-patch) build
3. **Fix discrimination** — returns 0 results on the fixed (post-patch) build

The search is also deliberately bounded: no open-ended LLM refinement loops. At most three targeted retries before the model is told to abandon the approach and try a structurally different detection strategy.

## Approach

For each target vulnerability, the model receives:

- The CyberGym task ID / CVE
- The project name and repo
- The CWE ID and a one-line root-cause description
- The vulnerability description (which function is involved, what triggers the bug)
- The crash info (sanitizer output and call stack)
- The patch diff, split into the removed (vulnerable) code and the added (fixed) code
- The baseline CodeQL query for that CWE class, as a starting point to build on rather than a blank page

It then works through five steps, encoded in [`codeql_prompt_template.md`](codeql_prompt_template.md):

1. **Parse the patch** — what did the fix add? That addition is almost always a bounds check, a size validation, an integer-overflow check, or a NULL check that was missing.
2. **Identify the vulnerable pattern** — trace the source (where the bad data enters), the sink (where the dangerous operation happens), and the taint flow connecting them.
3. **Diagnose the baseline's blind spot** — what structural pattern can the standard query not model, and why?
4. **Write the improved query** — extend the baseline with a more specific source, sink, and a sanitizer predicate derived directly from what the patch added, never from assumptions.
5. **Quality-check before output** — confirm the query imports `cpp` (not `java`), uses real `semmle.code.cpp.*` predicates, and that the sanitizer is tight enough to block only the fixed-code pattern.

Each candidate query is compiled and run against both the vulnerable and fixed builds. A failing query goes back through a second prompt ([`codeql_feedback_template.md`](codeql_feedback_template.md)) that diagnoses which of three failure modes occurred — missed the bug, false-positived on the fix, or the sanitizer did nothing at all — and applies exactly one targeted fix per retry, up to three attempts, before the model gets full autonomy to redesign the query from scratch.

## Results

Baseline vs. synthesized query detections across three target vulnerabilities (model: Claude Opus 4.7, CodeQL 2.25.3, CyberGym benchmark):

| Project / CWE | Vulnerability type | Baseline | Synthesized | False positives | Refinement iterations |
|---|---|---|---|---|---|
| pcre2 / CWE-125 | Out-of-bounds read | 0 | 1 | 0 | 2 |
| miniz / CWE-457 | Uninitialized variable | 0 | 1 | 0 | 5 |
| libxml2 / CWE-476 | NULL pointer dereference | 0 | 2 | 0 | 1 |
| **Overall** | | **0/3** | **3/3** | **0** | — |

The synthesized queries found all three bugs with zero false positives, against 0 of 3 for the baseline pack. Feeding only these high-confidence, patch-specific queries into the downstream triage stage also contributed to a roughly 90% cut in LLM API usage at the pipeline level, by eliminating broad, low-precision candidate generation before it started.

## Repository structure

```
.
├── codeql_prompt_template.md    # The 5-step patch-guided synthesis prompt
├── codeql_feedback_template.md  # The iterative retry/diagnosis prompt
├── baseline.ql                  # Template: paste the standard CWE query here
├── enhanced.ql                  # Template: paste the LLM-synthesized query here
├── collect_task_info.sh         # Gathers a CyberGym task's description, error
│                                 trace, and patch diff into one file for the prompt
├── setup_cybergym_task.py       # Downloads a CyberGym benchmark task (vulnerable +
│                                 fixed repo pair) from Hugging Face
└── final_queries/               # The actual baseline and synthesized queries used
    ├── libxml2_baseline.ql / libxml2_final-v1.ql
    ├── miniz_baseline.ql / miniz_final_v5.ql
    └── pcre2_baseline.ql / pcre2_final_v2.ql
```

## Usage

1. **Fetch a benchmark task.** Set `DATASET_GROUP` and `TASK_ID` in `setup_cybergym_task.py` and run it — it downloads the CyberGym task data from Hugging Face (`sunblaze-ucb/cybergym`) and extracts the vulnerable and fixed repo builds locally.
2. **Collect the task info.** Run `collect_task_info.sh` to pull the task's `description.txt`, `error.txt`, and `patch.diff` (plus your baseline query) into a single reference file.
3. **Paste the standard CWE query** for the vulnerability class into `baseline.ql`, sourced unmodified from the [official CodeQL query packs](https://github.com/github/codeql/tree/main/cpp/ql/src/Security/CWE).
4. **Fill in `codeql_prompt_template.md`** with the task info and baseline query, and submit it to an LLM.
5. **Compile and run** the resulting query against both the vulnerable and fixed builds.
6. **If it fails**, fill in `codeql_feedback_template.md` with the result counts and the previous query, and resubmit — up to three targeted retries before starting over with a different detection strategy.
7. **On success**, save the query into `final_queries/`.

## Full write-up

A longer version of this project — with the same problem/constraints/approach/outcome breakdown and the results table above — is on my [portfolio](https://cmwendy.vercel.app/?project=codeql-target-generation).

## Author

Wendy Contreras Martinez — [LinkedIn](https://www.linkedin.com/in/wcontrerasm) · [GitHub](https://github.com/CMWENDY)
