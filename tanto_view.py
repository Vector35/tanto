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
from tanto import menus

from binaryninjaui import FlowGraphWidget, View, ViewFrame, ViewType, ViewPaneHeaderSubtypeWidget, getApplicationFont, UIContext, UIAction, UIActionHandler, Menu, ContextMenuManager
from PySide6.QtWidgets import QWidget, QVBoxLayout
from PySide6.QtGui import QPalette, QPainter
from PySide6.QtCore import Qt

from binaryninja import BinaryView, Settings
from binaryninja.log import Logger, log_error
from binaryninja.enums import FunctionGraphType
from binaryninja.function import DisassemblySettings, FunctionViewType, Variable
from binaryninja.interaction import ChoiceField, TextLineField, get_form_input, get_text_line_input

from functools import partial
from typing import Callable, Optional


class TantoView(QWidget, View):
  slice_providers = []
  current_slice = None

  def __init__(self, parent: ViewFrame, bv: BinaryView, slices: list[tuple[str, str, 'tanto.slices.Slice']], logger: Logger):
    super().__init__(parent)
    View.__init__(self)
    self.setupView(self)
    View.setBinaryDataNavigable(self, True)
    self.setParent(parent)
    self.actionHandler = UIActionHandler()
    self.actionHandler.setupActionHandler(self)
    self.contextMenu = Menu()
    self.contextMenuManager = ContextMenuManager(self)
    self.actions = {}

    self.bv: BinaryView = bv
    self.slices: list[tuple[str, str, 'tanto.slices.Slice']] = slices
    self.log: Logger = logger
    self.disassembly_settings = DisassemblySettings()
    self.slice_menu = menus.SliceMenuWidget(self, self.actionHandler)

    self.flowgraph_widget = FlowGraphWidget(self, bv)
    self.flowgraph_widget.setContextMenuPolicy(Qt.NoContextMenu)
    self.flowgraph_widget.focusInEvent = self.focusInEvent
    self.clear_actions()

    # Prevent flowgraph's "No function selected" default message from showing
    self.flowgraph_widget_paintEvent = self.flowgraph_widget.paintEvent
    self.flowgraph_widget.paintEvent = self.helperPaintEvent

    layout = QVBoxLayout()
    layout.setContentsMargins(0, 0, 0, 0)
    self.setLayout(layout)
    self.layout().addWidget(self.flowgraph_widget)

  # TODO : selectable icons for each slice type instead of having to go through the drop down menu
  def helperPaintEvent(self, event):
    p = QPainter(self.flowgraph_widget.viewport())

    p.setFont(getApplicationFont(self.flowgraph_widget))
    p.setPen(self.flowgraph_widget.palette().color(QPalette.WindowText))

    line1 = "Welcome to Tanto!"
    line2 = f"To get started, select \"{menus.NEW_SLICE_TEXT}\" above!"
    text = f"{line1}\n{line2}"

    text_rect = p.boundingRect(self.rect(), Qt.AlignCenter | Qt.TextWordWrap, text)   # Calculate the position to center the text
    p.drawText(text_rect, Qt.AlignCenter | Qt.TextWordWrap, text)

  def getData(self) -> BinaryView:
    return self.bv

  def getCurrentOffset(self, offset: Optional[int] = None) -> int:
    if offset is None:
      offset = self.flowgraph_widget.getCurrentOffset()
    if self.current_slice is not None and self.current_slice.navigation_style == tanto.slices.NavigationStyle.FUNCTION_START:
      current_functions = self.bv.get_functions_containing(offset)
      if len(current_functions) > 0:
        offset = current_functions[0].start

    return offset

  def getSelectionOffsets(self):
    return self.flowgraph_widget.getSelectionOffsets()

  def getDisassemblySettings(self):
    return self.disassembly_settings

  def focusInEvent(self, event):
    super().focusInEvent(event)
    self.setup_actions()

  def getHeaderOptionsWidget(self) -> 'tanto.menus.OptionsWidget':
    return menus.OptionsWidget(self)

  def getHeaderSubtypeWidget(self) -> ViewPaneHeaderSubtypeWidget:
    return self.slice_menu

  def navigate(self, offset: int) -> bool:
    self.setup_right_click_menu()

    # Regen graph based on setting
    if self.current_slice is not None and self.current_slice.update_style == tanto.slices.UpdateStyle.ON_NAVIGATE:
      self.flowgraph_widget.setGraph(self.current_slice.get_flowgraph())

    self.flowgraph_widget.showAddress(self.getCurrentOffset(offset))
    return True

  def getCurrentFunction(self):
    if self.current_slice is not None and self.current_slice.navigation_style == tanto.slices.NavigationStyle.FUNCTION_START:
      if len(current_functions := self.bv.get_functions_containing(self.getCurrentOffset())) > 0:
        return current_functions[0]
    return self.flowgraph_widget.getCurrentFunction()

  def getILViewType(self):
    if self.current_slice is not None:
      return self.current_slice.get_il_view_type()
    return FunctionViewType(FunctionGraphType.InvalidILViewType)

  @classmethod
  def register_slice_type(cls, name: str, slicer: 'tanto.slices.Slice'):
    settings_title = f"Enable {name}"
    description = f"Enable or disable {name}."

    properties = f'{{"title" : "{settings_title}", "description" : "{description}", "type" : "boolean", "default" : true}}'
    Settings().register_setting(f"tanto.{name}.enabled", properties)

    if any([name == slicer_name for slicer_name, _ in cls.slice_providers]):
      log_error(f"Could not register slicer '{name}' due to naming conflict")
      return
    cls.slice_providers.append((name, slicer))
    cls.slice_providers.sort(key=lambda s: s[0])

  def create_slice(self, create_option_callback: Callable[[str], None]):
    # Prompt user for slice name and type
    slice_name_f = TextLineField("Slice Name")

    slice_type_f = ChoiceField("Slice Type", [slicer_name for slicer_name, _ in self.slice_providers if Settings().get_bool(f"tanto.{slicer_name}.enabled")])
    if not get_form_input([None, None, slice_name_f, slice_type_f], menus.NEW_SLICE_TEXT):
      return
    if any([slice_name_f.result == slice_name for slicer_name, slice_name, slicer in self.slices]):
      self.log.log_alert("Slices require unique names")
      return

    slice_name = slice_name_f.result
    slicer_name, slicer_class = [s for s in self.slice_providers if Settings().get_bool(f"tanto.{s[0]}.enabled")][slice_type_f.result]

    if slice_name == "":
      names = [e_name for e_slicer_name, e_name, _ in self.slices if e_slicer_name == slicer_name]
      for i in range(1, 1000):
        slice_name = f"{slicer_name} {i}"
        if slice_name not in names:
          break
      else:
        self.log.log_alert("Could not generate unique slice name")
        return

    # Change dropdown/menu selection text to new slice
    create_option_callback(slice_name)

    # Unregister old actions
    self.clear_actions()

    # Instantiate slicer class and save it with its names to our shared state from our parent
    self.current_slice = slicer_class(self)
    self.slices.append((slicer_name, slice_name, self.current_slice))

    # Register new actions
    self.setup_actions()

    # Enable the actual flowgraph rendering again and navigate the slice to wherever we currently are in the binary
    self.flowgraph_widget.paintEvent = self.flowgraph_widget_paintEvent
    self.flowgraph_widget.setGraph(self.current_slice.get_flowgraph())

  def switch_to_slice(self, name, change_option_callback: Callable[[str], None]):
    if not hasattr(self, 'slice_menu'):
      return
    self.flowgraph_widget.paintEvent = self.flowgraph_widget_paintEvent
    change_option_callback(name)
    for _slicer_name, slice_name, slicer in self.slices:
      if slice_name == name:

        # Unregister old global actions, register new ones
        self.clear_actions()
        self.current_slice = slicer
        self.setup_actions()

        self.flowgraph_widget.setGraph(self.current_slice.get_flowgraph())
        self.navigate(self.getCurrentOffset())
        return

  def rename_slice(self, change_option_callback: Callable[[], None]):
    i = 0
    name = self.slice_menu.get_current_slice_name()
    for slicer_name, slice_name, slicer in self.slices:
      if slice_name == name:
        break
      i += 1
    else:
      assert False  # This shouldn't be possible; attempted to renaming slice that doesn't currently exist

    if (new_name := get_text_line_input("New Name", "Rename Slice").decode('utf-8')) is not None:
      self.slices[i] = (slicer_name, new_name, slicer)
      change_option_callback()
    if slice_name in self.actions:
      self.actions[new_name] = self.actions[slice_name]
      del self.actions[slice_name]
    self.switch_to_slice(new_name, self.slice_menu.menu.create_slice)

  def delete_slice(self, change_option_callback: Callable[[], None]):
    i = 0
    name = list(self.slice_menu.menu.m_menu.getActions())[self.slice_menu.menu.index]
    for _slicer_name, slice_name, _slicer in self.slices:
      if slice_name == name:
        break
      i += 1
    else:
      assert False  # This shouldn't be possible; attempted to delete slice that doesn't currently exist
    del self.slices[i]
    if slice_name in self.actions:
      del self.actions[slice_name]

    if len(self.slices) == 0:
      self.flowgraph_widget.setGraph(None)
      self.flowgraph_widget.paintEvent = self.helperPaintEvent
      self.flowgraph_widget.repaint()
    change_option_callback()

  def contextMenuEvent(self, event):
    self.contextMenuManager.show(self.contextMenu, self.actionHandler)

  def setup_actions(self):
    # Navigate is called before the view is fully initialized, so we need to check if the slice menu exists
    # TODO : Check if this is actually fixing the same issue as the other hasattr check (circular initialization)
    if not hasattr(self, 'slice_menu'):
      return

    if (current_slice_name := self.slice_menu.get_current_slice_name()) != menus.NEW_SLICE_TEXT:
      if current_slice_name in self.actions:
        for name, action, is_valid, menu_group, menu_order in self.actions[current_slice_name]:
          self.__registrate_action(name, action, is_valid, menu_group, menu_order)
        self.setup_right_click_menu()

  def setup_right_click_menu(self):
    # Right click menu in main view
    if (current_slice_name := self.slice_menu.get_current_slice_name()) != menus.NEW_SLICE_TEXT:
      if current_slice_name in self.actions:
        context = UIContext.activeContext()
        if context is not None:
          view = context.getCurrentView()
          if view is not None:
            # Our contextMenu is not callable, but normal ones are...so we can abuse that
            if callable(context_menu := view.contextMenu):
              self.disassembly_settings = view.getDisassemblySettings()  # Since we know this is the main view area, we can cache this
              context_menu = context_menu()
              for name, _, _, menu_group, menu_order in self.actions[current_slice_name]:
                context_menu.addAction(f"Tanto\\{name}", menu_group, menu_order)

  def clear_actions(self):
    # Remove from Tanto context menu
    for action in self.contextMenu.getActions().keys():
      self.actionHandler.unbindAction(action)
      self.contextMenu.removeAction(action)

    # Remove from flowgraph_widget
    for action in self.flowgraph_widget.contextMenu().getActions().keys():
      # Do NOT unbind the action or we're needlessly removing functionality! (being able to rename and a bunch of other stuff)
      # self.flowgraph_widget.actionHandler().unbindAction(action)
      self.flowgraph_widget.contextMenu().removeAction(action)

    # Remove from menu bar
    for action in UIAction.getAllRegisteredActions():
      if action.startswith("Tanto") and action != "Tanto":
        UIActionHandler.globalActions().unbindAction(action)
        UIAction.unregisterAction(action)
        Menu.mainMenu("Plugins").removeAction(action)

    # Remove from main right click menu
    context = UIContext.activeContext()
    view = context.getCurrentView()
    if view is not None:
      if callable(context_menu := view.contextMenu):
        context_menu = context_menu()
        self.disassembly_settings = view.getDisassemblySettings()  # Since we know this is the main view area, we can cache this

      # Remove old buttons
      for action in context_menu.getActions().keys():
        if "Tanto" in action:
          context_menu.removeAction(action)

  def __registrate_action(self, name: str, action_wrapper, is_valid_wrapper, menu_group: str = "", menu_order: int = 0):
    # Plugin Menu
    UIAction.registerAction(f"Tanto\\{name}")
    UIActionHandler.globalActions().bindAction(f"Tanto\\{name}", UIAction(action_wrapper, is_valid_wrapper))
    Menu.mainMenu("Plugins").addAction(f"Tanto\\{name}", menu_group, menu_order)

    # Right click menu in flowgraph
    UIAction.registerAction(name)
    self.actionHandler.bindAction(name, UIAction(action_wrapper, is_valid_wrapper))
    self.contextMenu.addAction(name, menu_group, menu_order)

  def __register_action(self, name: str, action_wrapper, is_valid_wrapper, menu_group: str = "", menu_order: int = 0):
    current_slice_name = self.slice_menu.get_current_slice_name()
    assert current_slice_name != menus.NEW_SLICE_TEXT  # The update cycle has a bug if this is ever hit - make sure the menu callback is called before initializing/switching to a slice
    if current_slice_name in self.actions:
      self.actions[current_slice_name].append((name, action_wrapper, is_valid_wrapper, menu_group, menu_order))
    else:
      self.actions[current_slice_name] = [(name, action_wrapper, is_valid_wrapper, menu_group, menu_order)]

  def register_for_binary_view(self, name: str,
                               action: Callable[['BinaryView'], None],
                               is_valid: Optional[Callable[['BinaryView'], bool]] = None,
                               menu_group: str = "", menu_order: int = 0):

    def _binary_view_action_wrapper(action: Callable[['BinaryView'], None], context):
      action(tanto.helpers.get_current_binary_view())

    def _binary_view_is_valid_wrapper(is_valid: Optional[Callable[['BinaryView'], bool]], context) -> bool:
      if (bv := tanto.helpers.get_current_binary_view()) is None:
        return False
      return is_valid is None or is_valid(bv)

    self.__register_action(name, partial(_binary_view_action_wrapper, action), partial(_binary_view_is_valid_wrapper, is_valid), menu_group, menu_order)

  def register_for_function(self, name: str,
                            action: Callable[['BinaryView', 'tanto.helpers.AnyFunction'], None],
                            is_valid: Optional[Callable[['BinaryView', 'tanto.helpers.AnyFunction'], bool]] = None,
                            menu_group: str = "", menu_order: int = 0):

    def _function_action_wrapper(action: Callable[['BinaryView', 'tanto.helpers.AnyFunction'], None], context):
      action(tanto.helpers.get_current_binary_view(), tanto.helpers.get_current_il_function())

    def _function_is_valid_wrapper(is_valid: Optional[Callable[['BinaryView', 'tanto.helpers.AnyFunction'], bool]], context) -> bool:
      if (bv := tanto.helpers.get_current_binary_view()) is None or (func := tanto.helpers.get_current_il_function()) is None:
        return False
      return is_valid is None or is_valid(bv, func)

    self.__register_action(name, partial(_function_action_wrapper, action), partial(_function_is_valid_wrapper, is_valid), menu_group, menu_order)

  def register_for_basic_block(self, name: str,
                               action: Callable[['BinaryView', 'tanto.helpers.AnyBasicBlock'], None],
                               is_valid: Optional[Callable[['BinaryView', 'tanto.helpers.AnyBasicBlock'], bool]] = None,
                               menu_group: str = "", menu_order: int = 0):

    def _basic_block_action_wrapper(action: Callable[['BinaryView', 'tanto.helpers.AnyBasicBlock'], None], context):
      action(tanto.helpers.get_current_binary_view(), tanto.helpers.get_current_il_basic_block())

    def _basic_block_is_valid_wrapper(is_valid: Optional[Callable[['BinaryView', 'tanto.helpers.AnyBasicBlock'], bool]], context) -> bool:
      if (bv := tanto.helpers.get_current_binary_view()) is None or (bb := tanto.helpers.get_current_il_basic_block()) is None:
        return False
      return is_valid is None or is_valid(bv, bb)

    self.__register_action(name, partial(_basic_block_action_wrapper, action), partial(_basic_block_is_valid_wrapper, is_valid), menu_group, menu_order)

  def register_for_variable(self, name: str,
                            action: Callable[['BinaryView', Variable], None],
                            is_valid: Optional[Callable[['BinaryView', Variable], bool]] = None,
                            menu_group: str = "", menu_order: int = 0):

    def _variable_action_wrapper(action: Callable[['BinaryView', Variable], None], context):
      action(tanto.helpers.get_current_binary_view(), Variable.from_core_variable(tanto.helpers.get_current_il_function(), context.token.localVar))

    def _variable_is_valid_wrapper(is_valid: Optional[Callable[['BinaryView', Variable], bool]], context) -> bool:
      if (bv := tanto.helpers.get_current_binary_view()) is None or not context.token.localVarValid or (var := context.token.localVar) is None or (func := tanto.helpers.get_current_il_function()) is None:
        return False
      return is_valid is None or is_valid(bv, Variable.from_core_variable(func, var))

    self.__register_action(name, partial(_variable_action_wrapper, action), partial(_variable_is_valid_wrapper, is_valid), menu_group, menu_order)

  def register_for_address(self, name: str,
                           action: Callable[['BinaryView', int], None],
                           is_valid: Optional[Callable[['BinaryView', int], bool]] = None,
                           menu_group: str = "", menu_order: int = 0):

    def _addr_action_wrapper(action: Callable[['BinaryView', int], None], context):
      action(tanto.helpers.get_current_binary_view(), context.address)

    def _addr_is_valid_wrapper(is_valid: Optional[Callable[['BinaryView', int], bool]], context) -> bool:
      if (bv := tanto.helpers.get_current_binary_view()) is None or (addr := context.address) is None:
        return False
      return is_valid is None or is_valid(bv, addr)

    self.__register_action(name, partial(_addr_action_wrapper, action), partial(_addr_is_valid_wrapper, is_valid), menu_group, menu_order)


# Implements a ViewType; This gets initialized by binaryninja at startup and
# lives for the life of the program. I use this to store state for each file
# since the actual view/pane only lives for the duration you see it. And I'm
# not in the business of losing people's analysis data**! (**See TODO below)

# TODO : Save slices to DB (is there an on-save callback or would I write to
# the plugin metadata thing directly so it shows the 'unsaved changes' dot?)

# TODO : All the FlowGraphWidgets get deleted when the view is closed???
class TantoViewType(ViewType):
  def __init__(self):
    super().__init__("Tanto", "Tanto")
    self.data = {}

  def getPriority(self, bv: BinaryView, filename: str) -> int:
    return 1

  def create(self, bv: BinaryView, view_frame: ViewFrame) -> View:
    # TODO : Drop analysis data on bv close : Register a callback to run on bv close?

    if bv.file.session_id not in self.data:
      self.data[bv.file.session_id] = ([], Logger(bv.file.session_id, "Tanto"))
    return TantoView(view_frame, bv, *self.data[bv.file.session_id])
