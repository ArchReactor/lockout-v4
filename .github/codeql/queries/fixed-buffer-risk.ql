/**
 * @name Fixed-size buffer used with string operations
 * @description Identifies fixed-size char arrays that may receive
 *              unbounded string input from network or file sources.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id cpp/lockout-fixed-buffer-risk
 * @tags security
 *       external/cwe/cwe-120
 *       external/cwe/cwe-131
 */

import cpp

/**
 * A fixed-size character array field in a class.
 */
class FixedCharBuffer extends Field {
  int size;

  FixedCharBuffer() {
    exists(ArrayType at |
      this.getType() = at and
      at.getBaseType().getName() = "char" and
      size = at.getArraySize()
    )
  }

  int getBufferSize() { result = size }
}

/**
 * Dangerous string functions that don't check bounds.
 */
class DangerousStringFunction extends Function {
  DangerousStringFunction() {
    this.hasName([
      "strcpy", "strcat", "sprintf", "gets",
      "scanf", "sscanf", "fscanf"
    ])
  }
}

from FixedCharBuffer buf, FunctionCall call, DangerousStringFunction func
where
  call.getTarget() = func and
  exists(Expr arg |
    arg = call.getAnArgument() and
    (
      // Direct use of buffer
      arg.(VariableAccess).getTarget() = buf
      or
      // Use via 'this' pointer access (this->buffer)
      arg.(PointerFieldAccess).getTarget() = buf
    )
  )
select call,
  "Fixed-size buffer '" + buf.getName() + "' (" + buf.getBufferSize().toString() +
  " bytes) used with unsafe function '" + func.getName() + "'. Consider using bounded alternatives."
