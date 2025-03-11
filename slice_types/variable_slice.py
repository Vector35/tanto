# Copyright(c) 2022-2025 Vector 35 Inc
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
from tanto.slices import Slice
from tanto.tanto_view import TantoView

from binaryninjaui import getApplicationFont

from binaryninja import FlowGraph, FlowGraphNode, Function, FunctionViewType
from binaryninja.enums import HighlightStandardColor, FunctionGraphType
from binaryninja.commonil import Terminal, ControlFlow

from PySide6.QtGui import QPalette, QPainter
from PySide6.QtCore import Qt


class VariableBlockSlice(Slice):
  def __init__(self, parent: 'tanto.tanto_view.TantoView'):
    self.parent = parent
    self.bv = parent.bv
    self.flowgraph_widget = self.parent.flowgraph_widget
    self.flowgraph_widget_paintEvent = self.parent.flowgraph_widget_paintEvent
    self.flowgraph_widget.paintEvent = self.helperPaintEvent

    self.variables = []
    self.func = None

    parent.register_for_variable("Include Variable in Slice", self.include_variable, menu_group="TantoGroup0", menu_order=0)
    parent.register_for_variable("Remove Variable from Slice", self.remove_variable, menu_group="TantoGroup0", menu_order=1)
    parent.register_for_binary_view("Remove All Variables", self.clear, lambda bv: len(self.variables) > 0, "TantoGroup1", 2)

  def helperPaintEvent(self, event):
    p = QPainter(self.flowgraph_widget.viewport())

    p.setFont(getApplicationFont(self.flowgraph_widget))
    p.setPen(self.flowgraph_widget.palette().color(QPalette.WindowText))

    text = "Get started by right-clicking a variable and selecting 'Tanto -> Include Variable in Slice'"
    text_rect = p.boundingRect(self.flowgraph_widget.rect(), Qt.AlignCenter | Qt.TextWordWrap, text)   # Calculate the position to center the text
    p.drawText(text_rect, Qt.AlignCenter | Qt.TextWordWrap, text)

  def get_il_view_type(self) -> FunctionViewType:
    if self.func is None:
      return FunctionViewType(FunctionGraphType.InvalidILViewType)
    if isinstance(self.func, Function):
      return FunctionViewType(FunctionGraphType.NormalFunctionGraph)
    return FunctionViewType(self.func.il_form)

  def include_variable(self, bv, var):
    current_func = tanto.helpers.get_current_il_function()
    if self.func is None:
      self.func = current_func
    if current_func != self.func:
      return

    if var not in self.variables:
      self.variables.append(var)

    self.reset()

  def remove_variable(self, bv, var):
    current_func = tanto.helpers.get_current_il_function()
    if self.func is None:
      self.func = current_func
    if current_func != self.func:
      return

    if var in self.variables:
      self.variables.remove(var)

    self.reset()

  def reset(self):
    # Update graph, clear all highlights
    for bb in self.func:
      bb.set_auto_highlight(HighlightStandardColor.NoHighlightColor)
      for inst in tanto.helpers.get_insts(bb):
        if isinstance(self.func, tanto.helpers.ILFunction):
          self.func.source_function.set_auto_instr_highlight(inst.address, HighlightStandardColor.NoHighlightColor)
        else:
          self.func.set_auto_instr_highlight(inst.address, HighlightStandardColor.NoHighlightColor)
    # Update graph, regen graph and highlights
    self.flowgraph_widget.setGraph(self.get_flowgraph())

  def clear(self, bv):
    for bb in self.func:
      bb.set_auto_highlight(HighlightStandardColor.NoHighlightColor)
      for inst in tanto.helpers.get_insts(bb):
        if isinstance(self.func, tanto.helpers.ILFunction):
          self.func.source_function.set_auto_instr_highlight(inst.address, HighlightStandardColor.NoHighlightColor)
        else:
          self.func.set_auto_instr_highlight(inst.address, HighlightStandardColor.NoHighlightColor)

    self.variables.clear()
    self.func = None

    self.flowgraph_widget.paintEvent = self.helperPaintEvent
    self.flowgraph_widget.setGraph(None)
    # TODO : Call reset?

  def recover_subgraph_edges(self, block_index, function_slice):
    for bb in self.func:
      if bb.index == block_index:
        break
    else:
      # log_error("Could not find basic block")
      return []

    def reach_down(il_bb, function_slice, visited):
      if il_bb in visited:
        return set()
      if il_bb in function_slice:
        return set([il_bb])
      visited.add(il_bb)

      result = set()
      for edge in il_bb.outgoing_edges:
        result.update(reach_down(edge.target, function_slice, visited))
      return result

    return reach_down(bb, function_slice, set())

  def get_flowgraph(self) -> FlowGraph:
    if self.func is None or len(self.variables) == 0:
      self.flowgraph_widget.paintEvent = self.helperPaintEvent
      return
    else:
      self.flowgraph_widget.paintEvent = self.flowgraph_widget_paintEvent

    keep_indexes = set()
    for var in self.variables:
      for bb in self.func:
        for inst in bb:
          if self.func.il_form in [FunctionGraphType.LowLevelILSSAFormFunctionGraph, FunctionGraphType.MediumLevelILSSAFormFunctionGraph, FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph, FunctionGraphType.HighLevelILSSAFormFunctionGraph]:
            if self.func.is_ssa_var_live_at(var, inst.instr_index):
              keep_indexes.add(inst.instr_index)
          elif self.func.is_var_live_at(var, inst.instr_index):
            keep_indexes.add(inst.instr_index)

    new_graph = FlowGraph()
    if isinstance(self.func, Function):
      new_graph.function = self.func
    else:
      new_graph.function = self.func.source_function
      new_graph.il_function = self.func
    nodes = {}
    node_edges = {}
    nodes_with_lines = []
    function_slice = []
    for basic_block in self.func:
      new_node = FlowGraphNode(new_graph)

      # Edgy stuff
      edges = set()
      for edge in basic_block.outgoing_edges:
        edges.add(edge)
      node_edges[basic_block.index] = edges

      lines = basic_block.get_disassembly_text(tanto.helpers.get_disassembly_settings())
      for line in lines:
        line.highlight = HighlightStandardColor.NoHighlightColor

      # Pruning Basic Block Content
      saved_lines = []
      for inst in basic_block:
        if inst.instr_index in keep_indexes:
          if tanto.helpers.instruction_contains_var(self.variables, inst):
            saved_lines += [line for line in lines if line.il_instruction == inst]
            inst.function.source_function.set_auto_instr_highlight(inst.address, HighlightStandardColor.GreenHighlightColor)
          elif isinstance(inst, ControlFlow) and not isinstance(inst, Terminal):
            inst.function.source_function.set_auto_instr_highlight(inst.address, HighlightStandardColor.YellowHighlightColor)
            for line in [line for line in lines if line.il_instruction == inst]:
              for i in range(len(line.tokens)):
                line.tokens[i].confidence = 0
              saved_lines.append(line)

      new_node.lines = saved_lines
      if len(saved_lines) > 0:
        nodes[basic_block.index] = new_node
        nodes_with_lines.append(basic_block.index)
        function_slice.append(basic_block)
        new_graph.append(new_node)

    # Stitching the edges back together
    for index in nodes_with_lines:
      for edge in node_edges[index]:
        if edge.target.index in nodes_with_lines:
          nodes[index].add_outgoing_edge(edge.type, nodes[edge.target.index])
        else:
          outgoing_edges = self.recover_subgraph_edges(edge.target.index, function_slice)
          for target in outgoing_edges:
            nodes[index].add_outgoing_edge(edge.type, nodes[target.index])

    return new_graph


TantoView.register_slice_type("Variable Slice", VariableBlockSlice)
