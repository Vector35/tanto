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

from binaryninjaui import UIContext

from binaryninja import BinaryView
from binaryninja import Function, LowLevelILFunction, MediumLevelILFunction, HighLevelILFunction
from binaryninja import BasicBlock, LowLevelILBasicBlock, MediumLevelILBasicBlock, HighLevelILBasicBlock
from binaryninja import LowLevelILInstruction, MediumLevelILInstruction, HighLevelILInstruction
from binaryninja.log import log_error
from binaryninja.enums import FunctionGraphType

from typing import Union, Optional


BN_INVALID_EXPR = 0xffffffffffffffff

AnyFunction = Union[Function, LowLevelILFunction, MediumLevelILFunction, HighLevelILFunction]
ILFunction = Union[LowLevelILFunction, MediumLevelILFunction, HighLevelILFunction]
AnyBasicBlock = Union[BasicBlock, LowLevelILBasicBlock, MediumLevelILBasicBlock, HighLevelILBasicBlock]
ILBasicBlock = Union[LowLevelILBasicBlock, MediumLevelILBasicBlock, HighLevelILBasicBlock]
ILInstruction = Union[LowLevelILInstruction, MediumLevelILInstruction, HighLevelILInstruction]


def get_disassembly_settings():
  view_context = UIContext.activeContext()
  view = view_context.getCurrentView().widget()
  return view.getDisassemblySettings()


def get_insts(bb: BasicBlock) -> list[str]:  # TODO Results are not str...
  if bb is None:
    return None
  if isinstance(bb, BasicBlock):
    return bb.disassembly_text
  else:
    return bb


def get_basic_block_of_type(instr: LowLevelILInstruction, il_form: FunctionGraphType) -> Optional[AnyBasicBlock]:
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
  elif il_form == FunctionGraphType.InvalidILViewType:
    return None
  else:
    log_error(f"IL form {il_form.name} not supported in Tanto")
    return None


def get_function_of_type(func: Function, il_form: FunctionGraphType) -> Optional[AnyFunction]:
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
  elif il_form == FunctionGraphType.InvalidILViewType:
    return None
  else:
    log_error(f"IL form {il_form.name} not supported in Tanto")
    return None


def get_current_binary_view() -> Optional[BinaryView]:
  view_context = UIContext.activeContext()
  if view_context is None or view_context.getCurrentView() is None:
    return

  return view_context.getCurrentView().getData()


def get_current_source_function() -> Optional[Function]:
  view_context = UIContext.activeContext()
  if view_context is None or view_context.getCurrentView() is None:
    return

  if (function := view_context.getCurrentView().getCurrentFunction()) is not None:
    return function

  if (addr := get_current_address()) is not None and (bv := get_current_binary_view()) is not None and len(functions := bv.get_functions_containing(addr)) > 0:
    return functions[0]


def get_current_il_function() -> Optional[AnyFunction]:
  view_context = UIContext.activeContext()
  if view_context is None or view_context.getCurrentViewFrame() is None:
    return None
  if (function := view_context.getCurrentView().getCurrentFunction()) is None:
    return None

  return get_function_of_type(function, view_context.getCurrentViewFrame().getViewLocation().getILViewType().view_type)


def get_current_il_basic_block() -> Optional[BasicBlock]:
  func = get_current_il_function()
  addr = get_current_address()

  if func is None or addr is None or addr == 0:
    # log_error(f"Could not find function for location {hex(addr)}, {func}")
    return

  if isinstance(func, Function):
    llil = func.get_low_level_il_at(addr)
    bb = llil.il_basic_block.source_block
  else:
    llil = func.source_function.get_low_level_il_at(addr)
    bb = None
  if llil is not None and bb is None:
    try:
      bb = get_basic_block_of_type(llil, func.il_form)
    except:
      # Fail silently because this most often happens at points where the user isn't trying to perform the action (switching tabs, etc)
      return

  if llil is None or bb is None:
    log_error("Couldn't recover basic block. Please try again.")
    return

  return bb


def get_selected_inst() -> ILInstruction:
  view_context = UIContext.activeContext()
  if view_context is not None and view_context.getCurrentView() is not None:
    if (instr_index := view_context.getCurrentView().getCurrentILInstructionIndex()) != BN_INVALID_EXPR:
      return get_current_il_function()[instr_index]


def get_selected_expr() -> ILInstruction:
  def traverser(inst, text):
    if text in str(inst):
      return inst

  expr = None
  view_context = UIContext.activeContext()
  if view_context is not None and view_context.getCurrentView() is not None and (hts := view_context.getCurrentView().getHighlightTokenState()) is not None and hts.valid:
    if (inst := get_selected_inst()) is not None:
      for expr in inst.traverse(traverser, hts.token.text):
        pass
  if expr is not None:
    return expr
  return get_selected_inst()


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


def get_current_address() -> Optional[int]:
  view_context = UIContext.activeContext()
  if view_context is None or view_context.getCurrentView() is None:
    return

  return view_context.getCurrentView().getCurrentOffset()
