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

from .tanto_view import *
from .slices import *
from .menus import *
from .helpers import *
from .slice_types import *
from .api import *

from binaryninja import Settings
from binaryninjaui import ViewType
from binaryninja.scriptingprovider import PythonScriptingProvider, PythonScriptingInstance


Settings().register_group("tanto", "Tanto Settings")
ViewType.registerViewType(tanto.tanto_view.TantoViewType())


def _get_current_tanto_view(instance: PythonScriptingInstance):
  view_frame = instance.interpreter.locals["current_ui_view_frame"]
  current_view = instance.interpreter.locals["current_view"]
  if view_frame != None and current_view != None:
    view = view_frame.getViewForType(f"Tanto:{current_view.view_type}")
    if view != None:
      return TantoApiView(view)
  return None


PythonScriptingProvider.register_magic_variable(
  "current_tanto_view",
  _get_current_tanto_view,
  depends_on=[
    "current_view",
    "current_ui_view",
  ]
)


def _get_current_tanto_slice(instance: PythonScriptingInstance):
  tv = instance.interpreter.locals["current_tanto_view"]
  ts = tv.parent.current_slice
  if ts != None:
    return TantoApiSlice(ts)


PythonScriptingProvider.register_magic_variable(
  "current_tanto_slice",
  _get_current_tanto_slice,
  depends_on=[
    "current_tanto_view",
  ]
)

