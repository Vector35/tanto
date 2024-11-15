# Copyright(c) 2021-2024 Vector 35 Inc
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

# TODO : Green highlight is getting overwritten in some cases
# TODO : Type annotations

from binaryninjaui import UIActionHandler, UIAction, FlowGraphWidget, UIContext, Menu, WidgetPane, UIActionContext

import binaryninja as bn
from binaryninja import FlowGraph, FlowGraphNode, BinaryView, LowLevelILInstruction, Variable
from binaryninja import Function, LowLevelILFunction, MediumLevelILFunction, HighLevelILFunction
from binaryninja import BasicBlock, LowLevelILBasicBlock, MediumLevelILBasicBlock, HighLevelILBasicBlock
from binaryninja.log import log_error
from binaryninja.enums import FunctionGraphType, BranchType, HighlightStandardColor
from binaryninja.commonil import ControlFlow, Terminal

from PySide6.QtWidgets import QVBoxLayout, QWidget

from typing import Union, Tuple, Dict, Optional
from weakref import ref


ILFunction = Union[LowLevelILFunction, MediumLevelILFunction, HighLevelILFunction]
ILBasicBlock = Union[LowLevelILBasicBlock, MediumLevelILBasicBlock, HighLevelILBasicBlock]


PANES: Dict[int, Tuple[WidgetPane, 'SlicePaneWidget']] = dict()


def get_version() -> int:
  try:
    return bn.core_version_info().build
  except:
    return int(bn.core_version()[4:][:4])


# Compatibility for older versions
def get_view_type(vc) -> FunctionGraphType:
  if get_version() >= 6249:
    return vc.getCurrentViewFrame().getViewLocation().getILViewType().view_type
  return vc.getCurrentViewFrame().getViewLocation().getILViewType()


def address_wrapper(key: int = None, func = None):
  def get_bb(context: UIActionContext) -> Optional[Tuple[BinaryView, ILFunction, ILBasicBlock]]:
    view_context = context.context  # Chaining this fully in the next line causes this object to be deleted before it's done being used
    if context is None or context.context is None or context.binaryView is None or context.function is None or context.address is None or view_context.getCurrentViewFrame() is None:
      return

    bv = context.binaryView
    func = recover_current_function(context.function, get_view_type(view_context))
    addr: int = context.address

    if bv is None or func is None or addr == 0:
      log_error(f"Could not find function for location {hex(addr)}")
      return

    if isinstance(func, Function):
      llil = func.get_low_level_il_at(addr)
      bb = llil.il_basic_block.source_block
    else:
      llil = func.source_function.get_low_level_il_at(addr)
      bb = None
    if llil is not None and bb is None:
      try:
        bb = recover_current_basic_block(llil, func.il_form)
      except:
        # Fail silently because this most often happens at points where the user isn't trying to perform the action (switching tabs, etc)
        return

    if llil is None or bb is None:
      log_error("Couldn't recover basic block. Please try again.")
      return

    return (bv, func, bb)

  if func is None:
    return lambda context: get_bb(context) is not None
  else:
    return lambda context: func(PANES[key][1](), *get_bb(context))


def function_wrapper(key: int = None, func = None):
  def get_var(context: UIActionContext) -> Optional[Tuple[BinaryView, ILFunction, Variable]]:
    view_context = context.context  # Chaining this fully in the next line causes this object to be deleted before it's done being used
    if context is None or context.context is None or context.binaryView is None or context.function is None or context.address is None or view_context.getCurrentViewFrame() is None:
      return

    bv = context.binaryView
    func = recover_current_function(context.function, get_view_type(view_context))
    addr: int = context.address

    if bv is None or func is None or addr == 0:
      log_error(f"Could not find function for location {hex(addr)}")
      return

    var = get_current_variable_selection(func, view_context.getCurrentViewFrame().getCurrentViewInterface().getHighlightTokenState())
    if var is None:
      return

    return (bv, func, var)

  if func is None:
    return lambda context: get_var(context) is not None
  else:
    return lambda context: func(PANES[key][1](), *get_var(context))


def add_actions(key: int = 0, force: bool = False):
  prepostfix = "\\Tantō Slices"
  if key and force:
    postfix = f'{prepostfix} ({key})'
  elif not key and force:
    postfix = prepostfix
  else:
    postfix = ''

  UIAction.registerAction(f"Tanto\\Add Block to Slice{postfix}")
  UIAction.registerAction(f"Tanto\\Remove Block from Slice{postfix}")
  UIAction.registerAction(f"Tanto\\Add Variable to Slice{postfix}")
  UIAction.registerAction(f"Tanto\\Remove Variable from Slice{postfix}")
  UIAction.registerAction(f"Tanto\\Clear Selection{postfix}")

  UIActionHandler.globalActions().bindAction(f"Tanto\\Add Block to Slice{postfix}", UIAction(address_wrapper(key, SlicePaneWidget.add_block_to_whitelist), address_wrapper()))
  UIActionHandler.globalActions().bindAction(f"Tanto\\Remove Block from Slice{postfix}", UIAction(address_wrapper(key, SlicePaneWidget.add_block_to_blacklist), address_wrapper()))
  UIActionHandler.globalActions().bindAction(f"Tanto\\Add Variable to Slice{postfix}", UIAction(function_wrapper(key, SlicePaneWidget.add_variable_to_whitelist), function_wrapper()))
  UIActionHandler.globalActions().bindAction(f"Tanto\\Remove Variable from Slice{postfix}", UIAction(function_wrapper(key, SlicePaneWidget.remove_variable_from_whitelist), function_wrapper()))
  UIActionHandler.globalActions().bindAction(f"Tanto\\Clear Selection{postfix}", UIAction(lambda context: PANES[key][1]().clear_selection(), lambda context: True))

  parent_menu = "Tools"
  if get_version() >= 3505:
    parent_menu = "Plugins"
  Menu.mainMenu(parent_menu).addAction(f"Tanto\\Add Block to Slice{postfix}", "TantoGroup0", 0)
  Menu.mainMenu(parent_menu).addAction(f"Tanto\\Remove Block from Slice{postfix}", "TantoGroup0", 0)
  Menu.mainMenu(parent_menu).addAction(f"Tanto\\Add Variable to Slice{postfix}", "TantoGroup1", 1)
  Menu.mainMenu(parent_menu).addAction(f"Tanto\\Remove Variable from Slice{postfix}", "TantoGroup1", 1)
  Menu.mainMenu(parent_menu).addAction(f"Tanto\\Clear Selection{postfix}", "TantoGroup2", 2)


def setup_actions():
  parent_menu = "Tools"
  if get_version() >= 3505:
    parent_menu = "Plugins"

  # Unregister interaction methods
  for action in UIAction.getAllRegisteredActions():
    if action.startswith("Tanto") and action != "Tanto Slices":
      UIActionHandler.globalActions().unbindAction(action)
      UIAction.unregisterAction(action)
      Menu.mainMenu(parent_menu).removeAction(action)

  # Register current set
  for key in sorted(PANES.keys()):
    add_actions(key, force = len(PANES.keys()) > 1)

  UIAction.registerAction("Tanto\\Toggle All Highlights")
  UIAction.registerAction("Tanto\\Toggle Block Highlights")
  UIAction.registerAction("Tanto\\Toggle Block Selection Highlight")
  UIAction.registerAction("Tanto\\Toggle Line Highlights")
  UIAction.registerAction("Tanto\\Toggle Selection Highlight")
  UIAction.registerAction("Tanto\\Toggle Missing Children Highlight")
  UIAction.registerAction("Tanto\\Toggle Subgraph Replacement")
  UIActionHandler.globalActions().bindAction("Tanto\\Toggle All Highlights", UIAction(SlicePaneWidget.toggle_all_highlights, lambda *args: True))
  UIActionHandler.globalActions().bindAction("Tanto\\Toggle Block Highlights", UIAction(SlicePaneWidget.toggle_decomp_slice_highlight, lambda *args: True))
  UIActionHandler.globalActions().bindAction("Tanto\\Toggle Block Selection Highlight", UIAction(SlicePaneWidget.toggle_slice_block_selection_highlight, lambda *args: True))
  UIActionHandler.globalActions().bindAction("Tanto\\Toggle Line Highlights", UIAction(SlicePaneWidget.toggle_decomp_line_highlight, lambda *args: True))
  UIActionHandler.globalActions().bindAction("Tanto\\Toggle Selection Highlight", UIAction(SlicePaneWidget.toggle_decomp_block_selection_highlight, lambda *args: True))
  UIActionHandler.globalActions().bindAction("Tanto\\Toggle Missing Children Highlight", UIAction(SlicePaneWidget.toggle_decomp_missing_children_highlight, lambda *args: True))
  UIActionHandler.globalActions().bindAction("Tanto\\Toggle Subgraph Replacement", UIAction(SlicePaneWidget.toggle_subgraph_replacement, lambda *args: True))
  Menu.mainMenu(parent_menu).addAction("Tanto\\Toggle All Highlights", "TantoGroup3", 3)
  Menu.mainMenu(parent_menu).addAction("Tanto\\Toggle Block Highlights", "TantoGroup3", 3)
  Menu.mainMenu(parent_menu).addAction("Tanto\\Toggle Block Selection Highlight", "TantoGroup3", 3)
  Menu.mainMenu(parent_menu).addAction("Tanto\\Toggle Line Highlights", "TantoGroup3", 3)
  Menu.mainMenu(parent_menu).addAction("Tanto\\Toggle Selection Highlight", "TantoGroup3", 3)
  Menu.mainMenu(parent_menu).addAction("Tanto\\Toggle Missing Children Highlight", "TantoGroup3", 3)
  Menu.mainMenu(parent_menu).addAction("Tanto\\Toggle Subgraph Replacement", "TantoGroup4", 4)


def get_disassembly_settings():
  view_context = UIContext.activeContext()
  view = view_context.getCurrentView().widget()
  return view.getDisassemblySettings()


def recover_current_basic_block(instr: LowLevelILInstruction, il_form: FunctionGraphType):
  assert isinstance(il_form, FunctionGraphType)
  if il_form == FunctionGraphType.NormalFunctionGraph:
    return instr.il_basic_block.source_block
  elif il_form == FunctionGraphType.LiftedILFunctionGraph:
    return instr.function.source_function.get_lifted_il_at(instr.address).il_basic_block  # Seemingly bugged
  elif il_form == FunctionGraphType.LowLevelILFunctionGraph:
    return instr.il_basic_block
  elif il_form == FunctionGraphType.LowLevelILSSAFormFunctionGraph:
    return instr.ssa_form.il_basic_block
  elif il_form == FunctionGraphType.MappedMediumLevelILFunctionGraph:
    return instr.mapped_medium_level_il.il_basic_block
  elif il_form == FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph:
    return instr.mapped_medium_level_il.ssa_form.il_basic_block
  elif il_form == FunctionGraphType.MediumLevelILFunctionGraph:
    return instr.mlil.il_basic_block
  elif il_form == FunctionGraphType.MediumLevelILSSAFormFunctionGraph:
    return instr.mlil.ssa_form.il_basic_block
  elif il_form == FunctionGraphType.HighLevelILFunctionGraph:
    return instr.hlil.il_basic_block
  elif il_form == FunctionGraphType.HighLevelILSSAFormFunctionGraph:
    return instr.hlil.ssa_form.il_basic_block
  else:
    log_error(f"IL form {il_form.name} not supported in Tanto")
    return None


def recover_current_function(func: Function, il_form: FunctionGraphType):
  assert isinstance(il_form, FunctionGraphType)
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
    log_error(f"IL form {il_form.name} not supported in Tanto")
    return None


def get_current_variable_selection(func, hts):
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
        return
  except:
    return
  return var


def get_insts(bb):
  if bb is None:
    return None

  if isinstance(bb, BasicBlock):
    return bb.disassembly_text
  else:
    return bb


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


class SlicePaneWidget(QWidget):
  decomp_block_selection_highlight = True
  decomp_missing_children_highlight = True
  decomp_line_highlight = False
  decomp_slice_highlight = True
  slice_block_selection_highlight = True
  slice_missing_children_highlight = True
  subgraph_replacement = False

  def __init__(self, bv, n):
    # Actual initiation
    QWidget.__init__(self)  # TODO : Needs parent?

    self.actionHandler = UIActionHandler()
    self.actionHandler.setupActionHandler(self)

    # Pane number
    self.n = n

    # Slice vars
    self.bv: BinaryView = None
    self.func = None
    self.excluded_blocks = []
    self.included_blocks = []
    self.included_variables = []

    # Binary Graph Area
    self.flow_graph_widget = FlowGraphWidget(None, self.bv)

    # Prevent flowgraph's "No function selected" default message from showing
    self.flow_graph_widget_paintEvent = self.flow_graph_widget.paintEvent
    self.flow_graph_widget.paintEvent = lambda *args: None

    # Graph Area
    layout = QVBoxLayout()
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(self.flow_graph_widget, stretch=1)
    self.setLayout(layout)

    # Right Click Menu
    for action in self.flow_graph_widget.m_contextMenu.getActions().keys():
      self.flow_graph_widget.m_contextMenu.removeAction(action)

  @ staticmethod
  def createPane(context):
    if context.context and context.binaryView:

      # Get pane number
      global PANES
      keys = sorted(PANES.keys())
      for window_key, key in zip(keys, range(len(keys))):
        if key < window_key:
          n = key
          break
      else:
        n = len(keys)

      widget = SlicePaneWidget(context.binaryView, n)
      if n == 0:
        pane = WidgetPane(widget, "Tantō Slices")
      else:
        pane = WidgetPane(widget, f"Tantō Slices ({n})")

      PANES[n] = (ref(pane), ref(widget))
      context.context.openPane(pane)

      setup_actions()

  @ staticmethod
  def canCreatePane(context):
    # Right click menu hack
    if context is not None:
      view = context.view
      if view is not None:
        context_menu = view.contextMenu()

        if len(context_menu.getActions().keys()) == 0:
          return context.context and context.binaryView

        # Remove old buttons
        for action in context_menu.getActions().keys():
          if "Tanto" in action:
            context_menu.removeAction(action)

        # Add current set
        force = len(PANES.keys()) > 1
        for key in sorted(PANES.keys()):
          prepostfix = "\\Tantō Slices"
          if key and force:
            postfix = f'{prepostfix} ({key})'
          elif not key and force:
            postfix = prepostfix
          else:
            postfix = ''

          if UIAction.isActionRegistered(f"Tanto\\Add Block to Slice{postfix}"):
            context_menu.addAction(f"Tanto\\Add Block to Slice{postfix}", "TantoGroup0", 0)
            context_menu.addAction(f"Tanto\\Remove Block from Slice{postfix}", "TantoGroup0", 0)
            context_menu.addAction(f"Tanto\\Add Variable to Slice{postfix}", "TantoGroup1", 1)
            context_menu.addAction(f"Tanto\\Remove Variable from Slice{postfix}", "TantoGroup1", 1)
            context_menu.addAction(f"Tanto\\Clear Selection{postfix}", "TantoGroup2", 2)
      return context.context and context.binaryView
    else:
      return False

  def __del__(self):
    self.flow_graph_widget = None
    self.clear_selection()
    global PANES
    del PANES[self.n]
    setup_actions()

  @ classmethod
  def toggle_all_highlights(cls, _=None, __=None):
    count = 0
    if cls.decomp_block_selection_highlight:
      count += 1
    if cls.decomp_missing_children_highlight:
      count += 1
    if cls.decomp_line_highlight:
      count += 1
    if cls.decomp_slice_highlight:
      count += 1
    if cls.slice_block_selection_highlight:
      count += 1
    if cls.slice_missing_children_highlight:
      count += 1

    if count == 6:
      cls.decomp_block_selection_highlight = False
      cls.decomp_missing_children_highlight = False
      cls.decomp_line_highlight = False
      cls.decomp_slice_highlight = False
      cls.slice_block_selection_highlight = False
      cls.slice_missing_children_highlight = False
    else:
      cls.decomp_block_selection_highlight = True
      cls.decomp_missing_children_highlight = True
      cls.decomp_line_highlight = True
      cls.decomp_slice_highlight = True
      cls.slice_block_selection_highlight = True
      cls.slice_missing_children_highlight = True

    cls.update_all_graphs()

  @ classmethod
  def toggle_decomp_block_selection_highlight(cls, _):
    cls.decomp_block_selection_highlight = not cls.decomp_block_selection_highlight
    cls.update_all_graphs()

  @ classmethod
  def toggle_decomp_missing_children_highlight(cls, _):
    cls.decomp_missing_children_highlight = not cls.decomp_missing_children_highlight
    cls.update_all_graphs()

  @ classmethod
  def toggle_decomp_line_highlight(cls, _):
    cls.decomp_line_highlight = not cls.decomp_line_highlight
    cls.update_all_graphs()

  @ classmethod
  def toggle_decomp_slice_highlight(cls, _):
    cls.decomp_slice_highlight = not cls.decomp_slice_highlight
    cls.update_all_graphs()

  @ classmethod
  def toggle_slice_block_selection_highlight(cls, _):
    cls.slice_block_selection_highlight = not cls.slice_block_selection_highlight
    cls.update_all_graphs()

  @ classmethod
  def toggle_slice_missing_children_highlight(cls, _):
    cls.slice_missing_children_highlight = not cls.slice_missing_children_highlight
    cls.update_all_graphs()

  @ classmethod
  def toggle_subgraph_replacement(cls, _):
    cls.subgraph_replacement = not cls.subgraph_replacement
    cls.update_all_graphs()

  def contextMenuEvent(self, event):
    self.m_contextMenuManager.show(self.m_menu, self.actionHandler)

  def clear_graph(self):
    if self.flow_graph_widget is not None:
      self.flow_graph_widget.paintEvent = lambda *args: None
      self.flow_graph_widget.setGraph(None)

  def clear_selection(self):
    self.excluded_blocks.clear()
    self.included_blocks.clear()
    self.included_variables.clear()

    if self.func is None:
      return

    if isinstance(self.func, Function):
      func = self.func
    else:
      func = self.func.source_function

    for bb in self.func:
      bb.set_auto_highlight(HighlightStandardColor.NoHighlightColor)
      bb.set_user_highlight(HighlightStandardColor.NoHighlightColor)
      for inst in get_insts(bb):
        func.set_auto_instr_highlight(inst.address, HighlightStandardColor.NoHighlightColor)
    self.clear_graph()

  def add_block_to_whitelist(self, bv, func, bb):
    self.included_variables = []  # Only do variable slices or block slices at any given time

    if self.bv is not None and self.func is not None and (self.bv != bv or self.func != func):
      self.clear_selection()
    self.bv = bv
    self.func = func

    if bb in self.excluded_blocks:
      self.excluded_blocks.remove(bb)
    self.included_blocks.append(bb)
    self.update_graph()

  def add_block_to_blacklist(self, bv, func, bb):
    self.included_variables = []  # Only do variable slices or block slices at any given time

    if self.bv is not None and self.func is not None and (self.bv != bv or self.func != func):
      self.clear_selection()
    self.bv = bv
    self.func = func

    if bb in self.included_blocks:
      self.included_blocks.remove(bb)
    self.excluded_blocks.append(bb)
    self.update_graph()

  def add_variable_to_whitelist(self, bv, func, var):
    # Only do variable slices or block slices at any given time
    self.included_blocks = []
    self.excluded_blocks = []

    if self.bv is not None and self.func is not None and (self.bv != bv or self.func != func):
      self.clear_selection()
    self.bv = bv
    self.func = func

    if var is not None:
      if var not in self.included_variables:
        self.included_variables.append(var)
      self.update_graph()

  def remove_variable_from_whitelist(self, bv, func, var):
    # Only do variable slices or block slices at any given time
    self.included_blocks = []
    self.excluded_blocks = []

    if self.bv is not None and self.func is not None and (self.bv != bv or self.func != func):
      self.clear_selection()
      self.bv = bv
      self.func = func
      return
    self.bv = bv
    self.func = func

    if var is not None:
      if var in self.included_variables:
        self.included_variables.remove(var)
      self.update_graph()

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

  @staticmethod
  def update_all_graphs():
    for _, widget in PANES.values():
      widget().update_graph()

  def update_graph(self):
    self.flow_graph_widget.paintEvent = self.flow_graph_widget_paintEvent
    if isinstance(self.func, Function):
      func = self.func
    else:
      func = self.func.source_function

    for bb in self.func:
      bb.set_auto_highlight(HighlightStandardColor.NoHighlightColor)
      bb.set_user_highlight(HighlightStandardColor.NoHighlightColor)
      for inst in get_insts(bb):
        func.set_auto_instr_highlight(inst.address, HighlightStandardColor.NoHighlightColor)

    if len(self.included_variables) != 0:
      self.update_variables_slices_graph()
    elif len(self.included_blocks) != 0:
      self.update_block_slices_graph()

  def update_block_slices_graph(self):
    function_slice = self.calculate_basic_block_slice()

    if isinstance(self.func, Function):
      func = self.func
    else:
      func = self.func.source_function

    # Highlight features in original graph
    if self.decomp_slice_highlight:
      for bb in self.func:
        if bb in function_slice:
          if self.decomp_slice_highlight:
            bb.set_auto_highlight(HighlightStandardColor.CyanHighlightColor)
          if self.decomp_line_highlight:
            for inst in get_insts(bb):
              func.set_auto_instr_highlight(inst.address, HighlightStandardColor.CyanHighlightColor)
        else:
          if self.decomp_slice_highlight:
            bb.set_auto_highlight(HighlightStandardColor.RedHighlightColor)
          if self.decomp_line_highlight:
            for inst in get_insts(bb):
              func.set_auto_instr_highlight(inst.address, HighlightStandardColor.RedHighlightColor)
    if self.decomp_block_selection_highlight:
      for bb in self.included_blocks:
        bb.set_auto_highlight(HighlightStandardColor.GreenHighlightColor)
        if self.decomp_line_highlight:
          for inst in get_insts(bb):
            func.set_auto_instr_highlight(inst.address, HighlightStandardColor.GreenHighlightColor)
      for bb in self.excluded_blocks:
        bb.set_auto_highlight(HighlightStandardColor.WhiteHighlightColor)
        if self.decomp_line_highlight:
          for inst in get_insts(bb):
            func.set_auto_instr_highlight(inst.address, HighlightStandardColor.WhiteHighlightColor)

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
      if self.slice_block_selection_highlight and basic_block in self.included_blocks:
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
                    func.set_auto_instr_highlight(inst.address, HighlightStandardColor.YellowHighlightColor)

    self.flow_graph_widget.setGraph(new_graph)

  def update_variables_slices_graph(self):
    keep_indexes = set()
    for var in self.included_variables:
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
          if instruction_contains_var(self.included_variables, inst):
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


# Register Dock Widget
UIAction.registerAction("Tanto Slices")
UIActionHandler.globalActions().bindAction(
  "Tanto Slices", UIAction(SlicePaneWidget.createPane, SlicePaneWidget.canCreatePane)
)
Menu.mainMenu("View").addAction("Tanto Slices", "Pra")
