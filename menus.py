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

from binaryninjaui import Menu, ContextMenuManager, ClickableIcon, UIActionHandler, ViewPaneHeaderSubtypeWidget, UIAction, MenuHelper
from PySide6.QtGui import QImage, QKeySequence
from PySide6.QtCore import QSize
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout

NEW_SLICE_TEXT = "Create New Slice..."


class OptionsWidget(QWidget):
  def __init__(self, parent: 'tanto.tanto_view.TantoView'):
    super().__init__(parent)
    self.actionHandler = UIActionHandler()
    self.actionHandler.setupActionHandler(self)
    self.contextMenuManager = ContextMenuManager(self)

    self.menu = Menu()
    self.parent = parent

    UIAction.registerAction("Rename Slice")
    self.actionHandler.bindAction("Rename Slice", UIAction(
      lambda context: self.parent.rename_slice(SliceMenu.refresh),
      lambda context: len(self.parent.slices) > 0))
    self.menu.addAction("Rename Slice", "1")

    UIAction.registerAction("Delete Slice")
    self.actionHandler.bindAction("Delete Slice", UIAction(
      lambda context: self.parent.delete_slice(SliceMenu.refresh),
      lambda context: len(self.parent.slices) > 0))
    self.menu.addAction("Delete Slice", "2")

    # TODO : Cheeky tanto image instead of menu icon?
    # self.icon = ClickableIcon(QImage("./tanto.svg"), QSize(16, 16))
    self.icon = ClickableIcon(QImage(":/icons/images/menu.png"), QSize(16, 16))
    self.icon.clicked.connect(self.showMenu)

    layout = QHBoxLayout()
    layout.setContentsMargins(0, 0, 0, 0)
    self.setLayout(layout)
    self.layout().addWidget(self.icon)

  def showMenu(self):
    self.contextMenuManager.show(self.menu, self.actionHandler)

  def contextMenuEvent(self, event):
    self.showMenu()


# This represents the actual 'right click'/dropdown menu within the SliceMenuWidget.
# It gets its state from the parent (the TantoView itself), and there's a `refresh`
# classmethod which iterates all SliceMenu instances and updates their state,
# including if one pane deleted a slice that another was on. All the actions in this
# menu are wired back up to the parent with callbacks to update the display state
# after the main/parent state is updated internally.
class SliceMenu(MenuHelper):
  _instances = []

  def __init__(self, parent, actionHandler):
    super().__init__(parent)
    self.actionHandler = actionHandler
    self.contextMenuManager = ContextMenuManager(self)
    self.parent = parent
    self.index = 0

    # Register special-case action
    UIAction.registerAction(NEW_SLICE_TEXT, QKeySequence("Shift+K"))
    self.actionHandler.bindAction(NEW_SLICE_TEXT, UIAction(
      lambda context: self.parent.create_slice(self.create_slice),
      lambda context: True))
    self.m_menu.addAction(NEW_SLICE_TEXT, "ZLast")

    for (slicer_name, slice_name, slicer) in self.parent.slices:
      self.create_slice(slice_name)

    if len(self.parent.slices) > 0:
      self.parent.switch_to_slice(self.parent.slices[0][1], lambda n: None)

    self._instances.append(self)

  def __del__(self):
    self._instances.remove(self)

  def get_current_slice_name(self) -> str:
    return list(self.m_menu.getActions())[self.index]

  def get_index_of_slice(self, name: str) -> int:
    return list(self.m_menu.getActions()).index(name)

  @classmethod
  def refresh(cls, do_update_status = True):
    for inst in cls._instances:
      try:
        inst.m_menu
      except RuntimeError:
        continue
      existing_slice_names = set(inst.m_menu.getActions())
      existing_slice_names.remove(NEW_SLICE_TEXT)
      actual_slice_names = set([slice_name for (slicer_name, slice_name, slicer) in inst.parent.slices])
      selected_action = list(inst.m_menu.getActions())[inst.index]

      # Remove actions that don't exist
      for slice_name in existing_slice_names - actual_slice_names:
        inst.remove_slice(slice_name, False)

      # Add new actions
      for slice_name in sorted(list(actual_slice_names - existing_slice_names)):
        inst.create_slice(slice_name)

      if selected_action in actual_slice_names:
        inst.update_index(list(inst.m_menu.getActions()).index(selected_action))
      else:
        inst.update_index(inst.index)

      if do_update_status:
        inst.updateStatus()

  def update_index(self, index):
    # TODO : Some how to restore back to the last slice we were looking at?
    # global LAST_INDEX
    self.index = index
    if self.index >= len(self.m_menu.getActions()):
      self.index = 0
    if len(self.m_menu.getActions()) > 1 and self.get_current_slice_name() == NEW_SLICE_TEXT:
      self.index -= 1
    # LAST_INDEX = self.index

  def create_slice(self, name):
    UIAction.registerAction(name)
    self.actionHandler.bindAction(name, UIAction(
      lambda context: self.parent.switch_to_slice(name, self.switch_to_slice),
      lambda context: True))
    self.m_menu.addAction(name, "Slices")
    self.update_index(self.get_index_of_slice(name))
    self.setText(f" {name} ▾ ")

  def remove_slice(self, name, update_index=True):
    self.m_menu.removeAction(name)
    self.actionHandler.unbindAction(name)
    UIAction.unregisterAction(name)

    if update_index:  # When we recalculate
      self.update_index(self.index)

  def switch_to_slice(self, name):
    self.update_index(self.get_index_of_slice(name))
    self.updateStatus()

  def showMenu(self):
    self.refresh()
    if self.get_current_slice_name() == NEW_SLICE_TEXT:
      self.parent.create_slice(self.create_slice)
    else:
      self.contextMenuManager.show(self.m_menu, self.actionHandler)

  def updateStatus(self):
    self.refresh(False)
    if self.get_current_slice_name() == NEW_SLICE_TEXT:
      self.setText(f" {NEW_SLICE_TEXT} ")
    else:
      self.setText(" " + self.get_current_slice_name() + " ▾ ")


class SliceMenuWidget(ViewPaneHeaderSubtypeWidget):
  def __init__(self, parent, actionHandler):
    super().__init__()

    self.menu = SliceMenu(parent, actionHandler)
    self.setParent(parent)
    layout = QVBoxLayout()
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(self.menu)
    self.setLayout(layout)

  def updateStatus(self):
    self.menu.updateStatus()

  def get_current_slice_name(self) -> str:
    return list(self.menu.m_menu.getActions())[self.menu.index]
