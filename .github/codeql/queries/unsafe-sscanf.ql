/**
 * @name Unbounded sscanf string conversion
 * @description Using %s or %[...] in sscanf without field width limits
 *              can cause buffer overflows when parsing untrusted data.
 * @kind problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision high
 * @id cpp/lockout-unbounded-sscanf
 * @tags security
 *       external/cwe/cwe-120
 *       external/cwe/cwe-134
 */

import cpp

/**
 * A call to sscanf or similar scanning functions.
 */
class SscanfCall extends FunctionCall {
  SscanfCall() {
    this.getTarget().hasName(["sscanf", "fscanf", "scanf"])
  }

  /**
   * Gets the format string argument.
   */
  Expr getFormatArg() {
    this.getTarget().hasName("sscanf") and result = this.getArgument(1)
    or
    this.getTarget().hasName("fscanf") and result = this.getArgument(1)
    or
    this.getTarget().hasName("scanf") and result = this.getArgument(0)
  }

  /**
   * Gets the format string value if it's a string literal.
   */
  string getFormatString() {
    result = this.getFormatArg().(StringLiteral).getValue()
  }
}

/**
 * Check if a format string contains unbounded string conversions.
 * Looks for %s or %[...] without a numeric width specifier.
 */
predicate hasUnboundedStringConversion(string format) {
  // Match %s without width (e.g., "%s" but not "%39s")
  format.regexpMatch(".*%[^0-9\\[]*s.*")
  or
  // Match %[...] without width (e.g., "%[^|]" but not "%39[^|]")
  format.regexpMatch(".*%[^0-9]*\\[[^\\]]*\\].*")
}

from SscanfCall call, string format
where
  format = call.getFormatString() and
  hasUnboundedStringConversion(format)
select call,
  "sscanf uses unbounded format '" + format + "'. " +
  "Add field width limits (e.g., '%39s' or '%39[^|]') to prevent buffer overflow."
