/**
 * @name PCRE2 frame ovector memcpy with unclamped size
 * @description In pcre2_match.c, after a successful match, the internal
 *              stack-allocated frame ovector is copied into the external
 *              ovector. The vulnerable code computes the copy size from
 *              the externally-supplied `oveccount` alone using the
 *              expression `(oveccount - 1) * 2 * sizeof(PCRE2_SIZE)`.
 *              When the pattern has fewer capturing parentheses than
 *              `oveccount`, this reads past the end of the internal
 *              frame buffer (stack-buffer-overflow / CWE-125). The fix
 *              first clamps the slot count against `top_bracket + 1`
 *              and copies `(i - 2) * sizeof(PCRE2_SIZE)` bytes instead,
 *              so the unsafe `(... - 1) * 2 * sizeof(...)` shape
 *              disappears.
 * @kind problem
 * @id cpp/pcre2-ovector-memcpy-overflow
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @tags security
 *       external/cwe/cwe-125
 *       external/cwe/cwe-119
 */

import cpp

/** Holds if `e` (or a sub-expression of `e`) is a subtraction whose
 *  right operand is the constant `n`. */
predicate containsSubByConst(Expr e, string n) {
  exists(SubExpr se |
    se = e.getAChild*() and
    se.getRightOperand().getValue() = n
  )
}

/** Holds if `e` (or a sub-expression of `e`) is a multiplication that
 *  has the constant `n` as one of its operands. */
predicate containsMulByConst(Expr e, string n) {
  exists(MulExpr me |
    me = e.getAChild*() and
    me.getAnOperand().getValue() = n
  )
}

from FunctionCall memcpyCall, Expr sizeArg
where
  memcpyCall.getTarget().getName() = "memcpy" and
  memcpyCall.getFile().getBaseName() = "pcre2_match.c" and
  sizeArg = memcpyCall.getArgument(2) and
  // Pre-patch shape: `(X - 1) * 2 * sizeof(PCRE2_SIZE)`.
  // The literal `1` and the explicit literal `2` factor are both
  // characteristic of the unclamped, oveccount-derived size.
  containsSubByConst(sizeArg, "1") and
  containsMulByConst(sizeArg, "2") and
  // Post-patch shape: `(i - 2) * sizeof(PCRE2_SIZE)` — has `- 2` and no
  // separate `* 2` factor; reject anything matching that shape.
  not containsSubByConst(sizeArg, "2")
select memcpyCall,
  "memcpy in pcre2_match.c uses an oveccount-derived size of the form " +
  "'(X - 1) * 2 * sizeof(PCRE2_SIZE)', which is not clamped against the " +
  "pattern's top_bracket count and may read past the end of the internal " +
  "frame ovector (CWE-125)."