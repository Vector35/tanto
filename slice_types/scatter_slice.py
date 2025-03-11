# Copyright(c) 2024-2025 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and / or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import tanto
from tanto.tanto_view import TantoView

from binaryninja import FlowGraph, FlowGraphNode
from binaryninja.function import Function, DisassemblyTextLine
from binaryninja.enums import BranchType


class ScatterSlice(tanto.slices.Slice):
  def __init__(self, parent: 'tanto.tanto_view.TantoView'):
    self.navigation_style = tanto.slices.NavigationStyle.FUNCTION_START
    self.update_style = tanto.slices.UpdateStyle.ON_NAVIGATE

  def get_flowgraph(self) -> FlowGraph:
    if (function := tanto.helpers.get_current_source_function()) is None:
      print("No source function")
      return None

    new_graph = FlowGraph()
    nodes = {}
    added_edges = set()

    def add_function_node(function: Function) -> FlowGraphNode:
      if function not in nodes:
        new_node = FlowGraphNode(new_graph)
        new_node.lines = [DisassemblyTextLine(function.type_tokens, address=function.start)]
        new_graph.append(new_node)
        nodes[function] = new_node
      return nodes[function]

    visited = set()

    def add_callers(function: Function, level: int, max_level: int):
      visited.add(function)
      if level >= max_level:
        return
      current_node = add_function_node(function)

      # Add direct callers (incoming edges)
      for caller in function.callers:
        caller_node = add_function_node(caller)
        edge = (caller, function)
        if edge not in added_edges:
          caller_node.add_outgoing_edge(BranchType.CallDestination, current_node)
          added_edges.add(edge)
          if caller not in visited:
            add_callers(caller, level + 1, max_level)
            add_callees(caller, level + 1, max_level)

    def add_callees(function: Function, level: int, max_level: int):
      visited.add(function)
      if level >= max_level:
        return
      current_node = add_function_node(function)

      # Add direct callees (outgoing edges)
      for callee in function.callees:
        callee_node = add_function_node(callee)
        edge = (function, callee)
        if edge not in added_edges:
          current_node.add_outgoing_edge(BranchType.CallDestination, callee_node)
          added_edges.add(edge)
          if callee not in visited:
            add_callers(callee, level + 1, max_level)
            add_callees(callee, level + 1, max_level)

    # Add the middle function and its direct relationships
    add_callers(function, 0, 2)
    add_callees(function, 0, 2)

    # Optionally, add call relationships among remaining nodes (this is within the already added nodes)
    for function in nodes:
      node = nodes[function]
      for callee in function.callees:
        if callee in nodes:
          callee_node = nodes[callee]
          edge = (function, callee)
          if edge not in added_edges:
            node.add_outgoing_edge(BranchType.CallDestination, callee_node)
            added_edges.add(edge)

    return new_graph


TantoView.register_slice_type("Scatter Slice", ScatterSlice)
