/**
 * @name Unbounded strcpy from external source
 * @description Using strcpy without bounds checking on data from configuration
 *              or network sources can cause buffer overflows.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id cpp/lockout-unbounded-strcpy
 * @tags security
 *       external/cwe/cwe-120
 *       external/cwe/cwe-676
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

/**
 * A call to strcpy, which does not check buffer bounds.
 */
class StrcpyCall extends FunctionCall {
  StrcpyCall() {
    this.getTarget().hasName("strcpy")
  }

  Expr getDestination() { result = this.getArgument(0) }
  Expr getSource() { result = this.getArgument(1) }
}

/**
 * Identifies function parameters that receive external/configuration data.
 */
class ExternalDataSource extends DataFlow::Node {
  ExternalDataSource() {
    exists(Parameter p |
      p.getName().matches("%groups%") or
      p.getName().matches("%host%") or
      p.getName().matches("%search%") or
      p.getName().matches("%name%")
    |
      this.asParameter() = p
    )
  }
}

/**
 * Configuration for tracking tainted data to strcpy calls.
 */
class StrcpyTaintConfig extends TaintTracking::Configuration {
  StrcpyTaintConfig() { this = "StrcpyTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof ExternalDataSource
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(StrcpyCall call |
      sink.asExpr() = call.getSource()
    )
  }
}

from StrcpyTaintConfig config, DataFlow::PathNode source, DataFlow::PathNode sink, StrcpyCall call
where
  config.hasFlowPath(source, sink) and
  sink.getNode().asExpr() = call.getSource()
select call, source, sink,
  "Unbounded strcpy from $@ to fixed-size buffer. Use strncpy or snprintf with explicit length.",
  source.getNode(), "external source"
