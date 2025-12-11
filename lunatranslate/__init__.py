"""LunaTranslator hook integration layer.

This package exposes :class:`LunaHook`, a thin wrapper around
LunaTranslator's native LunaHost32/64.dll interface.  See
``luna_hook.py`` for implementation details.
"""

from .luna_hook import LunaHook  # noqa: F401