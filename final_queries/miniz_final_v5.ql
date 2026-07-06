/**
 * @name Miniz tinfl_decompress missing dist == 0 check
 * @description Detects a function that contains the comparison
 *              `dist > dist_from_out_buf_start` (the guard pattern
 *              found in miniz's tinfl_decompress) but does not contain
 *              any `dist == 0` (or `0 == dist`) comparison. The patch
 *              for this CWE-457 vulnerability adds an explicit
 *              `dist == 0` test so that when a Huffman-decoded
 *              distance of zero is fed back into the pointer
 *              arithmetic `(dist_from_out_buf_start - dist)` the
 *              function returns early instead of dereferencing
 *              uninitialised memory. When the `dist == 0` check is
 *              absent the function is vulnerable.
 * @kind problem
 * @id cpp/miniz-tinfl-missing-dist-zero-check
 * @problem.severity warning
 * @security-severity 7.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-457
 *       external/cwe/cwe-665
 */

import cpp

/**
 * Holds if the operation `op` has an operand whose textual
 * representation (or the textual representation of any of its
 * descendant sub-expressions) is exactly `text`.
 *
 * `Expr.toString()` returns the source-level token for accesses
 * (`"dist"` for a VariableAccess/FieldAccess/Parameter access
 * named `dist`) and for integer literals (`"0"` for the literal
 * zero), so this avoids the pitfalls of `getTarget().getName()`
 * and `Literal.getValue()` that may fail when the operand is
 * wrapped in a conversion or accessed via a struct field.
 */
predicate hasOperandWithText(Operation op, string text) {
  op.getAnOperand().toString() = text
  or
  exists(Expr child |
    child = op.getAnOperand().getAChild*() and
    child.toString() = text
  )
}

/**
 * Holds if `f` contains an equality comparison `dist == 0`
 * (or `0 == dist`).
 */
predicate functionHasDistEqZeroCheck(Function f) {
  exists(EQExpr eq |
    eq.getEnclosingFunction() = f and
    hasOperandWithText(eq, "dist") and
    hasOperandWithText(eq, "0")
  )
}

from GTExpr gt, Function f
where
  gt.getEnclosingFunction() = f and
  hasOperandWithText(gt, "dist") and
  hasOperandWithText(gt, "dist_from_out_buf_start") and
  // Vulnerable code lacks the `dist == 0` guard added by the patch.
  not functionHasDistEqZeroCheck(f)
select gt,
  "Comparison `dist > dist_from_out_buf_start` in $@ is not " +
  "accompanied by any `dist == 0` check; when dist is zero, " +
  "s_dist_base[0] returns 0 and the subsequent " +
  "(dist_from_out_buf_start - dist) pointer arithmetic produces " +
  "an invalid pointer that reads uninitialised memory.",
  f, f.getName()