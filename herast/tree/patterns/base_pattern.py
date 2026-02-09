from __future__ import annotations

import idaapi
import traceback
from herast.tree.match_context import MatchContext
import herast.tree.consts as consts


class BasePat:
	"""Base class for all patterns."""
	op = None

	def __init__(self, bind_name=None, debug=False, debug_msg=None, debug_trace_depth=0, check_op:int|None = None):
		"""

		:param bind_name: should successfully matched item be remembered
		:param debug: should provide debug information during matching
		:param debug_msg: additional message to print on debug
		:param debug_trace_depth: additional trace information on debug
		:param check_op: what item type to check. skips this check if None
		"""
		self.bind_name = bind_name
		self.check_op = check_op
		self.debug = debug
		self.debug_msg = debug_msg
		self.debug_trace_depth = debug_trace_depth

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
				rv = False

			if self.check_op is not None and item.op != self.check_op:
				rv = False

			rv = rv and func(self, item, ctx)

			if rv and self.bind_name is not None:
				rv = ctx.bind_item(self.bind_name, item)

			if self.debug:
				print(f'Matching {type(self).__name__} at 0x{item.ea:X}. Got item type \'{item.opname}\'; ' +
		  				("expected '" + consts.op2str.get(self.check_op, str(self.check_op)) + "'" if self.check_op is not None else "") + 
						f'. Result: {rv}')
			return rv
		return __perform_base_check

	@property
	def children(self):
		raise NotImplementedError("An abstract class doesn't have any children")