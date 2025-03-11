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


# This is the most basic slice implementation I could think of. It
# has an initialization step, where it chooses to drop the parent
# but maintains the bv ref, and it has a get_flowgraph step, where
# it generates its basic flow graph and returns it.

import tanto
from tanto.tanto_view import TantoView

from binaryninja import FlowGraph, FlowGraphNode
from binaryninja.function import DisassemblyTextLine
from binaryninja.enums import BranchType


class FullCallGraph(tanto.slices.Slice):
  def __init__(self, parent: 'tanto.tanto_view.TantoView'):
    self.bv = parent.bv
    self.navigation_style = tanto.slices.NavigationStyle.FUNCTION_START

  def get_flowgraph(self) -> FlowGraph:
    flowgraph = FlowGraph()
    nodes = {}

    for function in self.bv.functions:
      new_node = FlowGraphNode(flowgraph)
      new_node.lines = [DisassemblyTextLine(function.type_tokens, address=function.start)]
      flowgraph.append(new_node)
      nodes[f"{function.symbol.full_name}@{function.start}"] = new_node

    for function in self.bv.functions:
      node = nodes[f"{function.symbol.full_name}@{function.start}"]
      for edge in set(function.callees):
        node.add_outgoing_edge(BranchType.UnconditionalBranch, nodes[f"{edge.symbol.full_name}@{edge.start}"])

    return flowgraph


TantoView.register_slice_type("Full Call Graph", FullCallGraph)
