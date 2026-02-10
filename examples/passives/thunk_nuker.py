from __future__ import annotations
from herapi import *
import ida_funcs
import ida_bytes


def is_extern(f: ida_funcs.func_t) -> bool:
	if f.size() > 0x10:
		return False
	return len(set(ida_bytes.get_bytes(f.start_ea, f.size()))) < 2


class ReplacingScheme(Scheme):
	def __init__(self):
		pattern = CallPat(None, ignore_arguments=True, bind_name="func")
		super().__init__(pattern)

	def on_matched_item(self, item, ctx: MatchContext) -> ASTPatch|None:
		func_expr = ctx.get_item("func")
		func_ea = func_expr.x.obj_ea
		func = ida_funcs.get_func(func_ea)
		if func is None or not func.flags & ida_funcs.FUNC_THUNK:
			return None
		thunk = ida_funcs.calc_thunk_func_target(func)
		if not thunk or len(thunk) != 2:
			return None
		thunk = thunk[0]
		thunk_func = ida_funcs.get_func(thunk)
		if not thunk_func or is_extern(thunk_func):
			return None
		func_expr.x.obj_ea = thunk
		
register_storage_scheme("thunk_nuker", ReplacingScheme())