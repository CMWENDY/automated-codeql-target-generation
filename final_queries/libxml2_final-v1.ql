/**
 * @name SAX1 namePush instead of nameNsPush leaves pushTab slot uninitialized
 * @description In libxml2, the legacy SAX1 dispatch calls namePush(ctxt, name)
 *              in the else-branch of an `if (ctxt->sax2)` conditional whose
 *              then-branch calls nameNsPush. namePush only writes ctxt->nameTab
 *              and leaves ctxt->pushTab[ctxt->nameNr - 1] unpopulated, while
 *              xmlParseEndTag2 unconditionally reads that slot as a valid
 *              xmlStartTag struct, producing a NULL/near-NULL struct member
 *              dereference. The fix removes the SAX1 branch entirely and
 *              always calls nameNsPush.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision high
 * @id cpp/libxml2-sax1-namepush-pushtab-confusion
 * @tags reliability
 *       security
 *       external/cwe/cwe-476
 */

import cpp

/**
 * Holds if `e` is, or transitively contains, a field access of a field named `sax2`
 * (i.e. the conditional being inspected reads `ctxt->sax2` somewhere in its condition).
 */
predicate conditionMentionsSax2(Expr e) {
  exists(FieldAccess fa |
    fa.getTarget().getName() = "sax2" and
    (fa = e or fa.getParent+() = e)
  )
}

/**
 * Holds if statement `s` (or one of its descendants) contains a call to a
 * function named `name`.
 */
predicate stmtContainsCallTo(Stmt s, string name) {
  exists(FunctionCall fc |
    fc.getTarget().getName() = name and
    fc.getEnclosingStmt().getParent*() = s
  )
}

from FunctionCall wrongCall, IfStmt ifStmt, Stmt elseBranch, Stmt thenBranch
where
  // The "wrong" call is to namePush — the SAX1-only push that fails to populate
  // ctxt->pushTab as an xmlStartTag struct.
  wrongCall.getTarget().getName() = "namePush" and
  // It sits inside the else-branch of a conditional...
  ifStmt.getElse() = elseBranch and
  ifStmt.getThen() = thenBranch and
  wrongCall.getEnclosingStmt().getParent*() = elseBranch and
  // ...whose condition is gated on `ctxt->sax2` (or contains a sax2 field access)...
  conditionMentionsSax2(ifStmt.getCondition()) and
  // ...and whose then-branch calls nameNsPush — confirming a SAX2 vs. SAX1
  // dispatch site rather than an unrelated namePush use.
  stmtContainsCallTo(thenBranch, "nameNsPush") and
  // Both calls live in the same enclosing function (the element-start parser).
  exists(FunctionCall rightCall |
    rightCall.getTarget().getName() = "nameNsPush" and
    rightCall.getEnclosingStmt().getParent*() = thenBranch and
    rightCall.getEnclosingFunction() = wrongCall.getEnclosingFunction()
  )
select wrongCall,
  "Wrong push at SAX2/SAX1 dispatch: namePush is called in the else-branch of an " +
  "`if (ctxt->sax2)` whose then-branch calls nameNsPush. namePush does not populate " +
  "ctxt->pushTab, so xmlParseEndTag2's read of pushTab[nameNr-1] as xmlStartTag " +
  "dereferences an invalid/near-NULL address. Always call nameNsPush instead."