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

from enum import Enum

from binaryninja import FlowGraph, FunctionViewType
from binaryninja.enums import FunctionGraphType


#########
# Slice #
#########

# The slice class is an abstract class that users can implement to
# create Tanto plugins! Simply implement the functions below, then
# `call TantoView.register_slice_type` with a name for your slice type
# and a reference to your slice class.
#
# Currently you only need to implement `__init__` and `get_flowgraph`,
# You don't need to initialize the parent. This class will be
# instantiated by the user, and only deleted when they manually delete
# it or Binary Ninja exits. You can retain whatever state you want. I
# recommend caching flowgraphs if possible.
#
# Look for example implementations in ./slice_types/


class NavigationStyle(Enum):
  ABSOLUTE_ADDRESS = 0
  FUNCTION_START = 1


class UpdateStyle(Enum):
  MANUAL = 0
  ON_NAVIGATE = 1


class Slice():
  # This is really the only function you need to implement
  def get_flowgraph(self) -> FlowGraph:
    raise NotImplementedError

  # Completely optional to implement, but required for right click options to work within the slice
  def get_il_view_type(self) -> FunctionViewType:
    return FunctionViewType(FunctionGraphType.InvalidILViewType)

  # Config options

  @property
  def navigation_style(self):
    if hasattr(self, "_navigation_style"):
      return self._navigation_style
    return NavigationStyle.ABSOLUTE_ADDRESS

  @navigation_style.setter
  def navigation_style(self, value):
    self._navigation_style = value

  @property
  def update_style(self):
    if hasattr(self, "_update_style"):
      return self._update_style
    return UpdateStyle.MANUAL

  @update_style.setter
  def update_style(self, value):
    self._update_style = value
