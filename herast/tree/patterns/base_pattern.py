from __future__ import annotations

import idaapi
import traceback
from herast.tree.match_context import MatchContext
import herast.tree.consts as consts


class BasePat:
	"""Base class for all patterns."""
	op = None

	def __init__(self, bind_name=None, debug=False, check_op:int|None = None):
		"""

		:param bind_name: should successfully matched item be remembered
		:param debug: should provide debug information during matching
		:param check_op: what item type to check. skips this check if None
		"""
		self.bind_name = bind_name
		self.check_op = check_op
		self.debug = debug
		self.why = ''
		self.item_ea = None

	def check(self, item:idaapi.citem_t, ctx: MatchContext) -> bool:
		"""Base matching operation.

		:param item: AST item
		:param ctx: matching context
		"""
		raise NotImplementedError("This is an abstract class")

	@classmethod
	def get_opname(cls):
		return consts.op2str.get(cls.op, None)

	@staticmethod
	def base_check(func):
		"""Decorator for child classes instead of inheritance, since
		before and after calls are needed.
		"""
		def __perform_base_check(self:BasePat, item, ctx:MatchContext):
			rv = True
			if item is None:
				if not self.why:
					self.why = "Item is None"
				rv = False

			self.item_ea = item.ea

			if self.check_op is not None and item.op != self.check_op:
				if not self.why or self.why == "Item is None":
					self.why = f"Got item type '{item.opname}'" + item.dstr()
					self.why += f", expected '{consts.op2str.get(self.check_op, str(self.check_op))}'"				
				rv = False

			rv = rv and func(self, item, ctx)

			if rv and self.bind_name is not None:
				rv = ctx.bind_item(self.bind_name, item)

			do_debug = self.debug
			if do_debug and do_debug != True:
				if hasattr(do_debug, "__contains__") and item.ea in do_debug:
					do_debug = True
				elif item.ea != do_debug:
					do_debug = False
			
			if do_debug:					
				if not rv:
					for line in self._debug_tree():
						print(line)
				else:
					print(f"Pattern {type(self).__name__} matched at 0x{item.ea:X}")
			return rv
		return __perform_base_check

	def _debug_tree(self, level: int = 0) -> list[str]:
		"""Return a list of lines representing the failure tree for this pattern.

		Each line is already indented according to `level` (2 spaces per level).
		"""
		indent = '  ' * level
		line = f"{indent}{type(self).__name__}: {self.why}"
		if self.item_ea is not None and self.item_ea != idaapi.BADADDR:
			line += f" at 0x{self.item_ea:X}"
		lines = [line]
		self.why = ''
		try:
			kids = self.children
		except Exception:
			kids = ()
		if isinstance(kids, tuple):
			for kid in kids:
				if isinstance(kid, (list, tuple)):
					for k in kid:
						if isinstance(k, BasePat) and k.why:
							lines.extend(k._debug_tree(level + 1))
				elif isinstance(kid, BasePat):
					if kid.why:
						lines.extend(kid._debug_tree(level + 1))
		return lines

	@property
	def children(self):
		raise NotImplementedError("An abstract class doesn't have any children")