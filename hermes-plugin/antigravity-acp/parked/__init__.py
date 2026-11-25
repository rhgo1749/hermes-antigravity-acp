"""Parked-MCP engine (Design C): Hermes tools over a parked loopback MCP endpoint.

This subpackage is the DEFAULT execution engine behind the public
``antigravity-acp`` provider (and the compatibility id ``antigravity-acp-mcp``).
It was developed as the opt-in sibling plugin ``hermes-plugin/antigravity-acp-mcp``
(authored by Nanako0129, MIT-licensed; issues #81/#82/#83) and moved here when
Parked MCP became the default engine in plugin 0.9.0.  The Replay engine lives
in the parent package's flat modules and stays selectable as
``antigravity-acp-replay``.

Registration is explicit: the parent package's ``__init__.py`` calls
``register_parked_profiles()``; importing this package has no side effects.
"""

from __future__ import annotations
