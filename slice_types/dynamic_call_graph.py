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

from binaryninja import FlowGraph, FlowGraphNode, DisassemblyTextLine
from binaryninja.enums import BranchType

from PySide6.QtCore import QMimeData
from PySide6.QtGui import QDropEvent


class DynamicCallGraph(tanto.slices.Slice):
  def __init__(self, parent: 'tanto.tanto_view.TantoView'):
    self.parent = parent
    self.bv = parent.bv
    self.graph_funcs = set()
    self.excluded_funcs = set()

    self.navigation_style = tanto.slices.NavigationStyle.FUNCTION_START

    parent.setAcceptDrops(True)
    parent.dragEnterEvent = self.dragEnterEvent
    parent.dropEvent = self.dropEvent
    parent.flowgraph_widget.setAcceptDrops(True)
    parent.flowgraph_widget.dragEnterEvent = self.dragEnterEvent
    parent.flowgraph_widget.dropEvent = self.dropEvent

    parent.register_for_function("Include Function in Graph",
                                 self.include_function,
                                 lambda bv, func: self._to_source(func) not in self.graph_funcs,
                                 menu_group="TantoGroup0", menu_order=0)

    parent.register_for_function("Exclude Function from Graph",
                                 self.exclude_function,
                                 lambda bv, func: self._to_source(func) in self.graph_funcs and func not in self.excluded_funcs,
                                 menu_group="TantoGroup0", menu_order=1)

    parent.register_for_function("Include Callers",
                                 self.include_callers,
                                 lambda bv, func: self._to_source(func) in self.graph_funcs,
                                 menu_group="TantoGroup1", menu_order=0)
    parent.register_for_function("Include Callees",
                                 self.include_callees,
                                 lambda bv, func: self._to_source(func) in self.graph_funcs,
                                 menu_group="TantoGroup1", menu_order=1)
    parent.register_for_function("Include All Callers",
                                 self.include_all_callers,
                                 lambda bv, func: self._to_source(func) in self.graph_funcs,
                                 menu_group="TantoGroup2", menu_order=0)
    parent.register_for_function("Include All Callees",
                                 self.include_all_callees,
                                 lambda bv, func: self._to_source(func) in self.graph_funcs,
                                 menu_group="TantoGroup2", menu_order=1)

  def dragEnterEvent(self, event):
    event.accept()

  def dropEvent(self, event: QDropEvent):
    mime_data: QMimeData = event.mimeData()
    for addr in set(str(mime_data.data('application/component_tree_item'), 'utf-8').splitlines()):
      if addr.endswith('F'):
        func = self.bv.get_function_at(int(addr[:-1], 16))
        if func is not None:
          self.include_function(None, func)  # TODO : Validation that get func at returns not none
    event.accept()

  def _to_source(self, func):
    # If the function is an ILFunction, return its source function.
    return func.source_function if hasattr(func, "source_function") else func

  def include_function(self, bv, func):
    func = self._to_source(func)
    self.graph_funcs.add(func)
    if func in self.excluded_funcs:
      self.excluded_funcs.remove(func)
    self.update_graph()

  def exclude_function(self, bv, func):
    func = self._to_source(func)
    self.excluded_funcs.add(func)
    self.update_graph()

  def include_callers(self, bv, func):
    func = self._to_source(func)
    for caller in func.callers:
      self.graph_funcs.add(caller)
    self.update_graph()

  def include_callees(self, bv, func):
    func = self._to_source(func)
    for callee in func.callees:
      self.graph_funcs.add(callee)
    self.update_graph()

  def include_all_callers(self, bv, func):
    func = self._to_source(func)

    def dfs(f, visited):
      if f in visited:
        return
      visited.add(f)
      for caller in f.callers:
        self.graph_funcs.add(caller)
        dfs(caller, visited)
    dfs(func, set())
    self.update_graph()

  def include_all_callees(self, bv, func):
    func = self._to_source(func)

    def dfs(f, visited):
      if f in visited:
        return
      visited.add(f)
      for callee in f.callees:
        self.graph_funcs.add(callee)
        dfs(callee, visited)
    dfs(func, set())
    self.update_graph()

  def resolve_active_callees(self, func):
    result = set()
    visited = set()

    def dfs(curr):
      if curr in visited:
        return
      visited.add(curr)
      for callee in curr.callees:
        if callee in self.graph_funcs and callee not in self.excluded_funcs:
          result.add(callee)
        else:
          dfs(callee)
    dfs(func)
    result.discard(func)
    return result

  def update_graph(self):
    flowgraph = self.get_flowgraph()
    self.parent.flowgraph_widget.setGraph(flowgraph)
    # Optionally, navigate to the current offset.
    self.parent.navigate(self.parent.getCurrentOffset())

  def get_flowgraph(self) -> FlowGraph:
    active_funcs = {f for f in self.graph_funcs if f not in self.excluded_funcs}
    flowgraph = FlowGraph()
    nodes = {}

    for func in active_funcs:
      node = FlowGraphNode(flowgraph)
      node.lines = [DisassemblyTextLine(func.type_tokens, address=func.start)]
      flowgraph.append(node)
      nodes[func] = node

    for func in active_funcs:
      for target in self.resolve_active_callees(func):
        if func in nodes and target in nodes:
          nodes[func].add_outgoing_edge(BranchType.CallDestination, nodes[target])
    return flowgraph


TantoView.register_slice_type("Dynamic Call Graph", DynamicCallGraph)
