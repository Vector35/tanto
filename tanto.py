# Copyright(c) 2021-2022 Vector 35 Inc

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files(the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and / or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

from binaryninjaui import UIActionHandler, UIAction, DockContextHandler, FlowGraphWidget, DockHandler, UIContext, ViewFrame

from binaryninja import FunctionGraphType, BranchType, FlowGraph, FlowGraphNode, PluginCommand, BinaryView, HighlightStandardColor, Function
from binaryninja.log import log_error
from binaryninja.commonil import ControlFlow, Terminal

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QVBoxLayout, QWidget


# If the variable list and variable list item was exposed to the API, then we could make use of multi-selection by pulling variable objects out of the selection...instead we grab whatever token is currently selected
# UI_HIJACKED = False
# def hijack_variable_sidebar():
#   # Because we can have slices of multiple variables, it'd be nice if we could select them all at once
#   global UI_HIJACKED
#   if UI_HIJACKED:
#     return
#   try:
#     sidebar_context = Sidebar.current()
#     sidebar_type = sidebar_context.typeFromName("Variables")
#     sidebar_container = sidebar_context.container()
#     sidebar_context.activate(sidebar_type)
#     variable_sidebar = sidebar_container.widget(sidebar_type)
#     for widget in variable_sidebar.children():
#       if isinstance(widget, QListView):
#         break
#     widget.setSelectionMode(QAbstractItemView.ExtendedSelection)
#   except:
#     return
#   UI_HIJACKED = True


def get_disassembly_settings():
  view_context = UIContext.activeContext()
  view = view_context.getCurrentView().widget()
  return view.getDisassemblySettings()


def recover_current_basic_block(frame: ViewFrame, instr):
  il_form = frame.getCurrentViewInterface().getILViewType()
  if il_form == FunctionGraphType.NormalFunctionGraph:
    return instr.il_basic_block.source_block
  elif il_form == FunctionGraphType.LowLevelILFunctionGraph:
    return instr.il_basic_block
  elif il_form == FunctionGraphType.LiftedILFunctionGraph:
    return instr.function.source_function.get_lifted_il_at(instr.address).il_basic_block
  elif il_form == FunctionGraphType.LowLevelILSSAFormFunctionGraph:
    return None
  elif il_form == FunctionGraphType.MediumLevelILFunctionGraph:
    return instr.mlil.il_basic_block
  elif il_form == FunctionGraphType.MediumLevelILSSAFormFunctionGraph:
    return None
  elif il_form == FunctionGraphType.MappedMediumLevelILFunctionGraph:
    return None
  elif il_form == FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph:
    return None.ssa_form
  elif il_form == FunctionGraphType.HighLevelILFunctionGraph:
    return instr.hlil.il_basic_block
  elif il_form == FunctionGraphType.HighLevelILSSAFormFunctionGraph:
    return None
  else:
    return None


def recover_current_function(frame: ViewFrame, func):
  il_form = frame.getCurrentViewInterface().getILViewType()
  if il_form == FunctionGraphType.NormalFunctionGraph:
    return func
  elif il_form == FunctionGraphType.LowLevelILFunctionGraph:
    return func.llil
  elif il_form == FunctionGraphType.LiftedILFunctionGraph:
    return func.lifted_il
  elif il_form == FunctionGraphType.LowLevelILSSAFormFunctionGraph:
    return func.llil.ssa_form
  elif il_form == FunctionGraphType.MediumLevelILFunctionGraph:
    return func.mlil
  elif il_form == FunctionGraphType.MediumLevelILSSAFormFunctionGraph:
    return func.mlil.ssa_form
  elif il_form == FunctionGraphType.MappedMediumLevelILFunctionGraph:
    return func.llil.mapped_medium_level_il
  elif il_form == FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph:
    return func.llil.mapped_medium_level_il.ssa_form
  elif il_form == FunctionGraphType.HighLevelILFunctionGraph:
    return func.hlil
  elif il_form == FunctionGraphType.HighLevelILSSAFormFunctionGraph:
    return func.hlil.ssa_form
  else:
    return None


def get_current_variable_selection(func, frame):
  # If we could grab things out of the variable list:
  # sidebar_context = Sidebar.current()
  # sidebar_type = sidebar_context.typeFromName("Variables")
  # sidebar_container = sidebar_context.container()
  # sidebar_context.activate(sidebar_type)
  # variable_sidebar = sidebar_container.widget(sidebar_type)
  # for widget in variable_sidebar.children():
  #   if isinstance(widget, QListView):
  #     break

  # variable_list = get_variable_list(func)
  # return [variable_list[selection.row()] for selection in widget.selectionModel().selectedIndexes()]

  # Alas:
  hts = frame.getCurrentViewInterface().getHighlightTokenState()
  try:
    name = str(hts.token)
    for var in func.vars + func.aliased_vars + func.source_function.parameter_vars.vars:
      if var.name == name:
        break
    else:
      for var in func.ssa_vars:
        if f"{var.var.name}#{var.version}" == name:
          break
      else:
        log_error("Couldn't recover current selection!")
        return
  except:
    log_error("Failed to recover current selection!")  # Slightly different error to help debugging
    return
  return var


def instruction_contains_var(var_list, inst):
  for var in var_list:
    if inst.function.il_form in [FunctionGraphType.LowLevelILSSAFormFunctionGraph, FunctionGraphType.MediumLevelILSSAFormFunctionGraph, FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph, FunctionGraphType.HighLevelILSSAFormFunctionGraph]:
      for i in inst.function.get_ssa_var_uses(var) + [inst.function.get_ssa_var_definition(var)]:
        if inst.instr_index == i.instr_index:
          return True
    else:
      for i in inst.function.get_var_uses(var) + inst.function.get_var_definitions(var):
        if inst.instr_index == i.instr_index:
          return True
  return False


class SliceDockWidget(QWidget, DockContextHandler):
  def __init__(self, parent, name):
    # Actual initiation
    QWidget.__init__(self, parent)
    DockContextHandler.__init__(self, self, name)

    self.actionHandler = UIActionHandler()
    self.actionHandler.setupActionHandler(self)

    # My vars
    self.bv = None
    self.frame = None
    self.func = None
    self.block_blacklist = []
    self.block_whitelist = []
    self.variable_whitelist = []

    self.decomp_block_selection_highlight = True
    self.decomp_missing_children_highlight = True
    self.decomp_line_highlight = False
    self.decomp_slice_highlight = True
    self.slice_block_selection_highlight = True
    self.slice_missing_children_highlight = True
    self.subgraph_replacement = False

    # Binary Graph Area
    self.flow_graph_widget = FlowGraphWidget(self.frame, self.bv)

    # Graph Area
    layout = QVBoxLayout()
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(self.flow_graph_widget, stretch=1)
    self.setLayout(layout)

    # Right Click Menu
    self.flow_graph_widget.m_contextMenu.removeAction("Copy Address")

    self.flow_graph_widget.m_actionHandler.bindAction("Toggle All Highlights", UIAction(lambda context: self.toggle_all_highlights(), lambda context: len(self.block_whitelist) > 0))
    self.flow_graph_widget.m_actionHandler.bindAction("Toggle Block Selection Highlight", UIAction(lambda context: self.toggle_slice_block_selection_highlight(), lambda context: len(self.block_whitelist) > 0))
    self.flow_graph_widget.m_actionHandler.bindAction("Toggle Missing Children Highlight", UIAction(lambda context: self.toggle_slice_missing_children_highlight(), lambda context: len(self.block_whitelist) > 0))
    self.flow_graph_widget.m_actionHandler.bindAction("Toggle Subgraph Replacement", UIAction(lambda context: self.toggle_subgraph_replacement(), lambda context: len(self.block_whitelist) > 0))

    self.flow_graph_widget.m_contextMenu.addAction("Toggle All Highlights", "")
    self.flow_graph_widget.m_contextMenu.addAction("Toggle Block Selection Highlight", "")
    self.flow_graph_widget.m_contextMenu.addAction("Toggle Missing Children Highlight", "")
    self.flow_graph_widget.m_contextMenu.addAction("Toggle Subgraph Replacement", "")

  def shouldBeVisible(self, frame):
    # hijack_variable_sidebar()
    if frame is None:
      return False
    else:
      return True

  def notifyViewChanged(self, frame):
    # hijack_variable_sidebar()
    self.frame = frame
    if frame is None:
      self.bv = None
    else:
      self.bv = frame.getCurrentViewInterface().getData()
      try:
        current_address = frame.getSelectionOffsets()[0]
        self.func = recover_current_function(frame, self.bv.get_functions_containing(current_address)[0])
      except:
        pass

  def contextMenuEvent(self, event):
    self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

  def clear_graph(self):
    self.flow_graph_widget.setGraph(None)

  def clear_selection(self, bv: BinaryView, func: Function):
    self.block_blacklist.clear()
    self.block_whitelist.clear()
    self.variable_whitelist.clear()

    view_context = UIContext.activeContext()
    self.frame = view_context.getCurrentViewFrame()
    self.func = recover_current_function(self.frame, func)

    for bb in self.func:
      bb.set_auto_highlight(HighlightStandardColor.NoHighlightColor)
      bb.set_user_highlight(HighlightStandardColor.NoHighlightColor)
      for inst in bb:
        inst.function.source_function.set_auto_instr_highlight(inst.address, HighlightStandardColor.NoHighlightColor)
    self.clear_graph()

  def toggle_all_highlights(self, _=None, __=None):
    count = 0
    if self.decomp_block_selection_highlight:
      count += 1
    if self.decomp_missing_children_highlight:
      count += 1
    if self.decomp_line_highlight:
      count += 1
    if self.decomp_slice_highlight:
      count += 1
    if self.slice_block_selection_highlight:
      count += 1
    if self.slice_missing_children_highlight:
      count += 1

    if count == 6:
      self.decomp_block_selection_highlight = False
      self.decomp_missing_children_highlight = False
      self.decomp_line_highlight = False
      self.decomp_slice_highlight = False
      self.slice_block_selection_highlight = False
      self.slice_missing_children_highlight = False
    else:
      self.decomp_block_selection_highlight = True
      self.decomp_missing_children_highlight = True
      self.decomp_line_highlight = True
      self.decomp_slice_highlight = True
      self.slice_block_selection_highlight = True
      self.slice_missing_children_highlight = True

    self.update_graph()

  def toggle_decomp_block_selection_highlight(self, _, __):
    self.decomp_block_selection_highlight = not self.decomp_block_selection_highlight
    self.update_graph()

  def toggle_decomp_missing_children_highlight(self, _, __):
    self.decomp_missing_children_highlight = not self.decomp_missing_children_highlight
    self.update_graph()

  def toggle_decomp_line_highlight(self, _, __):
    self.decomp_line_highlight = not self.decomp_line_highlight
    self.update_graph()

  def toggle_decomp_slice_highlight(self, _, __):
    self.decomp_slice_highlight = not self.decomp_slice_highlight
    self.update_graph()

  def toggle_slice_block_selection_highlight(self):
    self.slice_block_selection_highlight = not self.slice_block_selection_highlight
    self.update_graph()

  def toggle_slice_missing_children_highlight(self):
    self.slice_missing_children_highlight = not self.slice_missing_children_highlight
    self.update_graph()

  def toggle_subgraph_replacement(self):
    self.subgraph_replacement = not self.subgraph_replacement
    self.update_graph()

  def add_block_to_whitelist(self, bv: BinaryView, addr: int):
    self.variable_whitelist = []  # Only do variable slices or block slices at any given time

    view_context = UIContext.activeContext()
    self.frame = view_context.getCurrentViewFrame()
    try:
      func = bv.get_functions_containing(addr)[0]
    except:
      log_error(f"Could not find function for location {hex(addr)}")
      return

    il_func = recover_current_function(self.frame, func)
    if self.func != il_func:
      self.clear_selection(None, func)
      self.func = il_func

    try:
      il_bb = recover_current_basic_block(self.frame, func.get_low_level_il_at(addr))
    except:
      log_error("Couldn't recover basic block. Please try again.")
      return
    if il_bb in self.block_blacklist:
      self.block_blacklist.remove(il_bb)
    self.block_whitelist.append(il_bb)
    self.update_graph()

  def add_block_to_blacklist(self, bv: BinaryView, addr: int):
    self.variable_whitelist = []  # Only do variable slices or block slices at any given time

    view_context = UIContext.activeContext()
    self.frame = view_context.getCurrentViewFrame()
    try:
      func = bv.get_functions_containing(addr)[0]
    except:
      log_error(f"Could not find function for location {hex(addr)}")

    il_func = recover_current_function(self.frame, func)
    if self.func != il_func:
      self.clear_selection(None, func)
      self.func = il_func

    il_bb = recover_current_basic_block(self.frame, func.get_low_level_il_at(addr))
    if il_bb in self.block_whitelist:
      self.block_whitelist.remove(il_bb)
    self.block_blacklist.append(il_bb)
    self.update_graph()

  def add_variable_to_whitelist(self, bv: BinaryView, func: Function):
    # Only do variable slices or block slices at any given time
    self.block_whitelist = []
    self.block_blacklist = []

    view_context = UIContext.activeContext()
    self.frame = view_context.getCurrentViewFrame()
    il_func = recover_current_function(self.frame, func)
    if self.func != il_func:
      self.clear_selection(None, func)
      self.func = il_func

    var = get_current_variable_selection(self.func, self.frame)
    if var is not None:
      if var not in self.variable_whitelist:
        self.variable_whitelist.append(var)
      self.update_graph()

  def remove_variable_from_whitelist(self, bv: BinaryView, func: int):
    # Only do variable slices or block slices at any given time
    self.block_whitelist = []
    self.block_blacklist = []

    view_context = UIContext.activeContext()
    self.frame = view_context.getCurrentViewFrame()
    il_func = recover_current_function(self.frame, func)
    if self.func != il_func:
      self.clear_selection(None, func)
      self.func = il_func
      return

    var = get_current_variable_selection(self.func, self.frame)
    if var is not None:
      if var in self.variable_whitelist:
        self.variable_whitelist.remove(var)
      self.update_graph()

  def calculate_basic_block_slice(self):
    def reach_up(il_bb, visited):
      if il_bb in visited or il_bb in self.block_blacklist:
        return []
      visited.append(il_bb)

      result = [il_bb]
      for edge in il_bb.incoming_edges:
        result += reach_up(edge.source, visited)
      return result

    def reach_down(il_bb, visited):
      if il_bb in visited or il_bb in self.block_blacklist:
        return []
      visited.append(il_bb)

      result = [il_bb]
      for edge in il_bb.outgoing_edges:
        result += reach_down(edge.target, visited)
      return result

    result = set()
    for bb in self.block_whitelist:
      result.update(set(reach_up(bb, []) + reach_down(bb, [])))
    return result

  def recover_subgraph_edges(self, block_index, function_slice):
    for bb in self.func:
      if bb.index == block_index:
        break
    else:
      log_error("Could not find basic block")
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

  def update_graph(self):
    for bb in self.func:
      bb.set_auto_highlight(HighlightStandardColor.NoHighlightColor)
      bb.set_user_highlight(HighlightStandardColor.NoHighlightColor)
      for inst in bb:
        inst.function.source_function.set_auto_instr_highlight(inst.address, HighlightStandardColor.NoHighlightColor)

    if len(self.variable_whitelist) != 0:
      self.update_variables_slices_graph()
    elif len(self.block_whitelist) != 0:
      self.update_block_slices_graph()

  def update_block_slices_graph(self):
    function_slice = self.calculate_basic_block_slice()

    # Highlight features in original graph
    if self.decomp_slice_highlight:
      for bb in self.func:
        if bb in function_slice:
          if self.decomp_slice_highlight:
            bb.set_auto_highlight(HighlightStandardColor.CyanHighlightColor)
          if self.decomp_line_highlight:
            for inst in bb:
              inst.function.source_function.set_auto_instr_highlight(inst.address, HighlightStandardColor.CyanHighlightColor)
        else:
          if self.decomp_slice_highlight:
            bb.set_auto_highlight(HighlightStandardColor.RedHighlightColor)
          if self.decomp_line_highlight:
            for inst in bb:
              inst.function.source_function.set_auto_instr_highlight(inst.address, HighlightStandardColor.RedHighlightColor)
    if self.decomp_block_selection_highlight:
      for bb in self.block_whitelist:
        bb.set_auto_highlight(HighlightStandardColor.GreenHighlightColor)
        if self.decomp_line_highlight:
          for inst in bb:
            inst.function.source_function.set_auto_instr_highlight(inst.address, HighlightStandardColor.GreenHighlightColor)
      for bb in self.block_blacklist:
        bb.set_auto_highlight(HighlightStandardColor.WhiteHighlightColor)
        if self.decomp_line_highlight:
          for inst in bb:
            inst.function.source_function.set_auto_instr_highlight(inst.address, HighlightStandardColor.WhiteHighlightColor)

    # Create new graph
    new_graph = FlowGraph()
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
      new_node.lines = basic_block.get_disassembly_text(get_disassembly_settings())
      for line in new_node.lines:
        line.highlight = HighlightStandardColor.NoHighlightColor

      # Duplicate selection highlight in new graph
      if self.slice_block_selection_highlight and basic_block in self.block_whitelist:
        new_node.highlight = HighlightStandardColor.GreenHighlightColor

      new_graph.append(new_node)

    # Tie edges together, highlight blocks with now-missing children, replace missing children with representational blocks
    for index, node in nodes.items():
      for edge in node_edges[index]:
        if edge.target.index in nodes:
          node.add_outgoing_edge(edge.type, nodes[edge.target.index])
        else:
          if self.subgraph_replacement:
            outgoing_edges = self.recover_subgraph_edges(edge.target.index, function_slice)
            new_node = FlowGraphNode(new_graph)
            new_node.highlight = HighlightStandardColor.RedHighlightColor
            for target in outgoing_edges:
              new_node.add_outgoing_edge(BranchType.UnresolvedBranch, nodes[target.index])
            new_graph.append(new_node)
            node.add_outgoing_edge(edge.type, new_node)

          if self.slice_missing_children_highlight:
            node.highlight = HighlightStandardColor.YellowHighlightColor

          if self.decomp_missing_children_highlight:
            for basic_block in function_slice:
              if basic_block.index == index:
                basic_block.set_auto_highlight(HighlightStandardColor.YellowHighlightColor)
                if self.decomp_line_highlight:
                  for inst in basic_block:
                    inst.function.source_function.set_auto_instr_highlight(inst.address, HighlightStandardColor.YellowHighlightColor)

    self.flow_graph_widget.setGraph(new_graph)

  def update_variables_slices_graph(self):
    keep_indexes = set()
    for var in self.variable_whitelist:
      for bb in self.func:
        for inst in bb:
          if self.func.il_form in [FunctionGraphType.LowLevelILSSAFormFunctionGraph, FunctionGraphType.MediumLevelILSSAFormFunctionGraph, FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph, FunctionGraphType.HighLevelILSSAFormFunctionGraph]:
            if self.func.is_ssa_var_live_at(var, inst.instr_index):
              keep_indexes.add(inst.instr_index)
          elif self.func.is_var_live_at(var, inst.instr_index):
            keep_indexes.add(inst.instr_index)

    new_graph = FlowGraph()
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

      lines = basic_block.get_disassembly_text(get_disassembly_settings())
      for line in lines:
        line.highlight = HighlightStandardColor.NoHighlightColor

      # Pruning Basic Block Content
      saved_lines = []
      for inst in basic_block:
        if inst.instr_index in keep_indexes:
          if instruction_contains_var(self.variable_whitelist, inst):
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

    self.flow_graph_widget.setGraph(new_graph)


# Register Docker Widget
dock_handler = DockHandler.getActiveDockHandler()
parent = dock_handler.parent()
slice_widget = SliceDockWidget(parent, "Slices")
dock_handler.addDockWidget(slice_widget, Qt.BottomDockWidgetArea, Qt.Horizontal, True, False)

# Register interaction methods
PluginCommand.register_for_address("Function Slices\\Block Slices\\Add block to slice", "", slice_widget.add_block_to_whitelist)
PluginCommand.register_for_address("Function Slices\\Block Slices\\Remove block from slice", "", slice_widget.add_block_to_blacklist)

PluginCommand.register_for_function("Function Slices\\Variable Slices\\Add variable to slice", "", slice_widget.add_variable_to_whitelist)
PluginCommand.register_for_function("Function Slices\\Variable Slices\\Remove variable from slice", "", slice_widget.remove_variable_from_whitelist)

PluginCommand.register_for_function("Function Slices\\Clear Selection", "", slice_widget.clear_selection)

PluginCommand.register_for_function("Function Slices\\Toggle All Highlights", "", slice_widget.toggle_all_highlights)
PluginCommand.register_for_function("Function Slices\\Toggle Block Highlights", "", slice_widget.toggle_decomp_slice_highlight)
PluginCommand.register_for_function("Function Slices\\Toggle Line Highlights", "", slice_widget.toggle_decomp_line_highlight)
PluginCommand.register_for_function("Function Slices\\Toggle Selection Highlight", "", slice_widget.toggle_decomp_block_selection_highlight)
PluginCommand.register_for_function("Function Slices\\Toggle Missing Children Highlight", "", slice_widget.toggle_decomp_missing_children_highlight)
