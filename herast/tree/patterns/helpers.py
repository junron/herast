import idaapi

from herast.tree.patterns.base_pattern import BasePat
from herast.tree.match_context import MatchContext
from herast.tree.patterns.expressions import AsgPat, CallPat
from herast.tree.patterns.instructions import ExprInsPat


class IntPat(BasePat):
	"""Pattern for expression, that could be interpreted as integer."""
	def __init__(self, value=None, **kwargs):
		super().__init__(**kwargs)
		self.value = value

	@BasePat.base_check
	def check(self, item, ctx: MatchContext) -> bool:
		if item.op not in (idaapi.cot_num, idaapi.cot_obj):
			self.why = "Item is not a number or object"
			return False

		if self.value is None:
			return True

		if item.op == idaapi.cot_num:
			check_value = item.n._value
		else:
			check_value = item.obj_ea
		if self.value != check_value:
			self.why = f"Value mismatch: expected {self.value}, got {check_value}"
			return False
		return True


class StringPat(BasePat):
	"""Pattern for expression that could be interpreted as string."""
	def __init__(self, str_value=None, minlen=5, **kwargs):
		super().__init__(**kwargs)
		self.str_value = str_value
		self.minlen = minlen

	@BasePat.base_check
	def check(self, item, ctx: MatchContext) -> bool:
		if item.op == idaapi.cot_obj:
			item.obj_ea
			name = item.print1(None)
			name = idaapi.tag_remove(name)
			name = idaapi.str2user(name)
		elif item.op == idaapi.cot_str:
			name = item.string
		else:
			self.why = "Item is not a string or object"
			return False

		if self.str_value is None:
			if len(name) >= self.minlen:
				return True
			self.why = f"String shorter than minlen {self.minlen}"
			return False
		else:
			if self.str_value == name:
				return True
			self.why = f"String mismatch: expected {self.str_value}, got {name}"
			return False


class StructFieldAccessPat(BasePat):
	"""Pattern for structure field access either by pointer or by reference."""
	def __init__(self, struct_type=None, member_offset=None, **kwargs):
		super().__init__(**kwargs)
		self.struct_type = struct_type
		self.member_offset = member_offset

	@BasePat.base_check
	def check(self, item, ctx: MatchContext) -> bool:
		if item.op != idaapi.cot_memptr and item.op != idaapi.cot_memref:
			self.why = "Not a memory reference or pointer"
			return False

		stype = item.x.type
		if stype.is_ptr():
			stype = stype.get_pointed_object()

		if not stype.is_struct():
			self.why = "Target type is not a struct"
			return False

		if self.member_offset is not None and self.member_offset != item.m:
			self.why = f"Member offset mismatch: expected {self.member_offset}, got {item.m}"
			return False

		if self.struct_type is None:
			return True

		if isinstance(self.struct_type, str) and self.struct_type == str(stype):
			return True

		if self.struct_type == stype:
			return True

		self.why = "Struct type mismatch"
		return False

def CallInsnPat(*args, **kwargs):
	"""Pseudopattern for quite popular operation of
	Expression Instruction with Call Expression
	"""
	return ExprInsPat(CallPat(*args, **kwargs), debug=kwargs.get('debug', False))

def AsgInsnPat(x, y, **kwargs):
	"""Pseudopattern for quite popular operation of
	Expression Instruction with Assignment Expression
	"""
	return ExprInsPat(AsgPat(x, y, **kwargs), debug=kwargs.get('debug', False))