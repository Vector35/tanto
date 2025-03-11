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

from binaryninja import FlowGraph, FlowGraphNode, Function, FunctionViewType
from binaryninja.enums import HighlightStandardColor, FunctionGraphType

from binaryninjaui import getApplicationFont
from PySide6.QtGui import QPalette, QPainter
from PySide6.QtCore import Qt

# TODO : Work on edges?
# TODO : Add option that blacklists all other switch targets
# TODO : Add highlight options back


class BasicBlockSlice(Slice):
  def __init__(self, parent: 'tanto.tanto_view.TantoView'):
    self.parent = parent
    self.bv = parent.bv
    self.flowgraph_widget = parent.flowgraph_widget
    self.flowgraph_widget_paintEvent = parent.flowgraph_widget_paintEvent
    self.flowgraph_widget.paintEvent = self.helperPaintEvent

    self.excluded_blocks = []
    self.included_blocks = []
    self.func = None

    parent.register_for_basic_block("Include Block in Slice", self.include_block, lambda bv, bb: bb in self.excluded_blocks or bb not in self.included_blocks, "TantoGroup0", 0)
    parent.register_for_basic_block("Exclude Block from Slice", self.exclude_block, lambda bv, bb: bb in self.included_blocks or bb not in self.excluded_blocks, "TantoGroup0", 1)
    parent.register_for_basic_block("Reset Block State", self.reset_block, lambda bv, bb: bb in self.included_blocks or bb in self.excluded_blocks, "TantoGroup1", 2)
    parent.register_for_binary_view("Clear All Block States", self.clear, lambda bv: len(self.included_blocks) + len(self.excluded_blocks) > 0, "TantoGroup2", 3)

  def helperPaintEvent(self, event):
    p = QPainter(self.flowgraph_widget.viewport())

    p.setFont(getApplicationFont(self.flowgraph_widget))
    p.setPen(self.flowgraph_widget.palette().color(QPalette.WindowText))

    text = "Get started by right-clicking a basic block and selecting 'Tanto -> Include Block in Slice'"
    text_rect = p.boundingRect(self.flowgraph_widget.rect(), Qt.AlignCenter | Qt.TextWordWrap, text)   # Calculate the position to center the text
    p.drawText(text_rect, Qt.AlignCenter | Qt.TextWordWrap, text)

  def get_il_view_type(self) -> FunctionViewType:
    if self.func is None:
      return FunctionViewType(FunctionGraphType.InvalidILViewType)
    if isinstance(self.func, Function):
      return FunctionViewType(FunctionGraphType.NormalFunctionGraph)
    return FunctionViewType(self.func.il_form)

  def include_block(self, bv, bb):
    if self.func is None and bb is not None:
      if bb.is_il:
        self.func = bb.il_function
      else:
        self.func = bb.function
    if bb is None or (bb.is_il and bb.il_function != self.func) or (not bb.is_il and bb.function != self.func):
      return

    if bb in self.excluded_blocks:
      self.excluded_blocks.remove(bb)
    self.included_blocks.append(bb)

    self.reset()

  def exclude_block(self, bv, bb):
    if self.func is None and bb is not None:
      if bb.is_il:
        self.func = bb.il_function
      else:
        self.func = bb.function
    if bb is None or (bb.is_il and bb.il_function != self.func) or (not bb.is_il and bb.function != self.func):
      return

    if bb in self.included_blocks:
      self.included_blocks.remove(bb)
    self.excluded_blocks.append(bb)

    self.reset()

  def reset_block(self, bv, bb):
    if self.func is None and bb is not None:
      if bb.is_il:
        self.func = bb.il_function
      else:
        self.func = bb.function
    if bb is None or (bb.is_il and bb.il_function != self.func) or (not bb.is_il and bb.function != self.func):
      return

    if bb in self.excluded_blocks:
      self.excluded_blocks.remove(bb)
    if bb in self.included_blocks:
      self.included_blocks.remove(bb)

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

    self.excluded_blocks.clear()
    self.included_blocks.clear()
    self.func = None

    self.flowgraph_widget.paintEvent = self.helperPaintEvent
    self.flowgraph_widget.setGraph(None)

  def calculate_basic_block_slice(self):
    def reach_up(il_bb, visited):
      if il_bb in visited or il_bb in self.excluded_blocks:
        return []
      visited.append(il_bb)

      result = [il_bb]
      for edge in il_bb.incoming_edges:
        result += reach_up(edge.source, visited)
      return result

    def reach_down(il_bb, visited):
      if il_bb in visited or il_bb in self.excluded_blocks:
        return []
      visited.append(il_bb)

      result = [il_bb]
      for edge in il_bb.outgoing_edges:
        result += reach_down(edge.target, visited)
      return result

    result = set()
    for bb in self.included_blocks:
      result.update(set(reach_up(bb, []) + reach_down(bb, [])))
    return result

  def get_flowgraph(self) -> FlowGraph:
    if self.func is None or len(self.included_blocks) + len(self.excluded_blocks) == 0:
      self.flowgraph_widget.paintEvent = self.helperPaintEvent
      return
    else:
      self.flowgraph_widget.paintEvent = self.flowgraph_widget_paintEvent

    function_slice = sorted(self.calculate_basic_block_slice(), key=lambda block: len(block.incoming_edges) != 0)

    # Highlight features in original graph
    # if self.decomp_slice_highlight:
    for bb in self.func:
      if bb in function_slice:
        # if self.decomp_slice_highlight:
        bb.set_auto_highlight(HighlightStandardColor.CyanHighlightColor)
      else:
        # if self.decomp_slice_highlight:
        bb.set_auto_highlight(HighlightStandardColor.RedHighlightColor)
    # if self.decomp_block_selection_highlight:
    for bb in self.included_blocks:
      bb.set_auto_highlight(HighlightStandardColor.GreenHighlightColor)
    for bb in self.excluded_blocks:
      bb.set_auto_highlight(HighlightStandardColor.WhiteHighlightColor)

    # Create new graph
    new_graph = FlowGraph()
    if isinstance(self.func, Function):
      new_graph.function = self.func
    else:
      new_graph.function = self.func.source_function
      new_graph.il_function = self.func
    nodes = {}
    node_edges = {}
    for basic_block in function_slice:
      new_node = FlowGraphNode(new_graph)

      # Edgy stuff
      nodes[basic_block.index] = new_node
      edges = set()
      for edge in basic_block.outgoing_edges:
        edges.add(edge)
      node_edges[basic_block.index] = edges

      # Copy over lines
      new_node.lines = basic_block.get_disassembly_text(tanto.helpers.get_disassembly_settings())
      for line in new_node.lines:
        line.highlight = HighlightStandardColor.NoHighlightColor

      # Duplicate selection highlight in new graph
      if basic_block in self.included_blocks:
        new_node.highlight = HighlightStandardColor.GreenHighlightColor

      new_graph.append(new_node)

    # Tie edges together, highlight blocks with now-missing children, replace missing children with representational blocks
    for index, node in nodes.items():
      for edge in node_edges[index]:
        if edge.target.index in nodes:
          node.add_outgoing_edge(edge.type, nodes[edge.target.index])
        else:
          node.highlight = HighlightStandardColor.YellowHighlightColor

          for basic_block in function_slice:
            if basic_block.index == index:
              basic_block.set_auto_highlight(HighlightStandardColor.YellowHighlightColor)

    return new_graph


TantoView.register_slice_type("Basic Block Slice", BasicBlockSlice)
