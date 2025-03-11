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

from binaryninja import FlowGraph, FlowGraphNode, DisassemblyTextLine, FunctionViewType
from binaryninja.enums import BranchType, FunctionGraphType


class SourceToSinkGraph(tanto.slices.Slice):
  def __init__(self, parent: 'tanto.tanto_view.TantoView'):
    super().__init__()
    self.parent = parent
    self.flowgraph_widget = self.parent.flowgraph_widget
    self.sources = set()
    self.sinks = set()

    self.navigation_style = tanto.slices.NavigationStyle.FUNCTION_START

    parent.register_for_function("Add Function as Source", self.add_function_as_source, menu_group="TantoGroup0", menu_order=0)
    parent.register_for_function("Add Function as Sink", self.add_function_as_sink, menu_group="TantoGroup0", menu_order=1)
    parent.register_for_function("Reset Function State", self.reset_function_state, menu_group="TantoGroup1", menu_order=2)
    parent.register_for_binary_view("Clear All", self.clear_all, menu_group="TantoGroup2", menu_order=3)

  def get_il_view_type(self) -> FunctionViewType:
    return FunctionViewType(FunctionGraphType.NormalFunctionGraph)

  def add_function_as_source(self, bv, func):
    if isinstance(func, tanto.helpers.ILFunction):
      func = func.source_function
    self.sources.add(func)
    self.update_graph()

  def add_function_as_sink(self, bv, func):
    if isinstance(func, tanto.helpers.ILFunction):
      func = func.source_function
    self.sinks.add(func)
    self.update_graph()

  def reset_function_state(self, bv, func):
    if isinstance(func, tanto.helpers.ILFunction):
      func = func.source_function
    if func in self.sources:
      self.sources.remove(func)
    if func in self.sinks:
      self.sinks.remove(func)
    self.update_graph()

  def clear_all(self, bv=None):
    self.sources.clear()
    self.sinks.clear()
    self.update_graph()

  def update_graph(self):
    flowgraph = self.get_flowgraph()
    self.flowgraph_widget.setGraph(flowgraph)
    if flowgraph:
      self.parent.navigate(self.parent.getCurrentOffset())

  def get_flowgraph(self):
    if not self.sources and not self.sinks:
      return None

    flowgraph = FlowGraph()
    nodes = {}
    edges = set()

    def add_node(function):
      key = f"{function.symbol.full_name}@{function.start}"
      if key not in nodes:
        new_node = FlowGraphNode(flowgraph)
        new_node.lines = [DisassemblyTextLine(function.type_tokens, address=function.start)]
        flowgraph.append(new_node)
        nodes[key] = new_node
      return nodes[key]

    def add_edge(source_func, target_func):
      edge_key = (source_func.start, target_func.start)
      if edge_key not in edges:
        source_node = add_node(source_func)
        target_node = add_node(target_func)
        source_node.add_outgoing_edge(BranchType.CallDestination, target_node)
        edges.add(edge_key)

    def traverse_funcs(func, visited, direction):
      if func in visited:
        return visited[func]

      visited[func] = set()

      if direction == 'down':
        call_edges = func.callees
      else:
        call_edges = func.callers

      for edge in call_edges:
        if edge not in visited:
          visited[func].add(edge)
          if direction == 'down':
            add_edge(func, edge)  # Edge from func to callee
          else:
            add_edge(edge, func)  # Edge from caller to func
          traverse_funcs(edge, visited, direction)

      return visited[func]

    # If both sources and sinks are provided, find paths between them
    if self.sources and self.sinks:
      for source in self.sources:
        for sink in self.sinks:
          paths = self.find_paths_from_source_to_sink(source, sink, set())
          for path in paths:
            for i in range(len(path) - 1):
              add_edge(path[i], path[i + 1])

    else:
      # If only sources are provided, show all paths from them
      if self.sources:
        for source in self.sources:
          traverse_funcs(source, {}, 'down')

      # If only sinks are provided, show all paths to them
      if self.sinks:
        for sink in self.sinks:
          traverse_funcs(sink, {}, 'up')

    return flowgraph

  def find_paths_from_source_to_sink(self, source, sink, visited):
    if source == sink:
      return [[source]]

    if source in visited:
      return []

    visited.add(source)
    paths = []
    for callee in source.callees:
      sub_paths = self.find_paths_from_source_to_sink(callee, sink, visited)
      for sub_path in sub_paths:
        paths.append([source] + sub_path)

    visited.remove(source)
    return paths


TantoView.register_slice_type("Source to Sink Graph", SourceToSinkGraph)
