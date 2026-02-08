from __future__ import annotations
from herapi import *
import re


class ReplacingScheme(Scheme):
	def __init__(self):
		"""
		pattern of form:
		if (x == 13) or if (x != 13)
		"""
		pattern = IfPat(
			OrPat(EqPat(VarPat(), NumPat(13)),ObjPat("giTerminalDebug"))
		)
		# NePat(VarPat(), NumPat(13) )
		# pattern = SeqPat(ExprInsPat(AsgPat(VarPat(), PtrPat(AnyPat()))), IfPat())
		super().__init__(pattern)

	def on_matched_item(self, item, ctx: MatchContext) -> ASTPatch|None:
		print()
		dstr = item.dstr()
		print("aaa", dstr, item.ea)
		print()
		if "giTerminalDebug" in dstr[:20]:
			return ASTPatch.replace_instr(item, make_call_helper_instr("__nothing"))
		match = re.search(r"__syslog_chk\((.+?)\);", dstr)
		match = match.group(1).replace("\"", "'") if match else ""
		# __syslog_chk(158, 2, "%s:%d (euid=%u)(pid=%d)(%m)!!Failed [%s], err=%m\n", "synocalendar.cpp", 584, v78, v77, "gpwebapiPostAction->run()");
		print()
		# Add inline comment
		
		return ASTPatch.replace_instr(item, make_call_helper_instr("__syslog_chk"))

register_storage_scheme("cpp_error", ReplacingScheme())