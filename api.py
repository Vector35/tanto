import tanto

import binaryninja
from binaryninja import BinaryView, Variable

from typing import Callable, Optional, Tuple


class TantoApiSliceAction:

  def __init__(self, name: str, action: Callable[..., None], validate: Optional[Callable[..., bool]] = None):
    self._name = name
    self._action = action
    self._validate = validate

  def __call__(self, *args) -> bool:
    if self._validate and not self._validate(*args):
      return False
    self._action(*args)
    return True


class TantoApiSlice:

  def __init__(self, parent: 'tanto.slices.Slice'):
    self.parent = parent
    self._actions = {n: TantoApiSliceAction(n, *self.parent.actions[n]) for n in self.parent.actions}

  def __call__(self, action: str, *args):
    return self._actions[action](*args)

  @property
  def actions(self) -> list:
    return list(self._actions.keys())

  @property
  def flowgraph(self) -> 'binaryninja.flowgraph.FlowGraph':
    return self.parent.get_flowgraph()


class TantoApiView:

  def __init__(self, parent: 'tanto.tanto_view.TantoView'):
    self.parent = parent

  def get_slice_by_name(self, name: str) -> Optional[TantoApiSlice]:
    for _slicer_name, slice_name, slicer in self.parent.slices:
      if slice_name == name:
        return TantoApiSlice(slicer)
    return None
