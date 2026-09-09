"""Backward-compatibility shim: :class:`OllamaManager` now lives in the backends package.

New code should import from :mod:`oasis.backends` (the factory) or
:mod:`oasis.backends.ollama_backend` directly. This module keeps the historical
import paths working (``from oasis.ollama_manager import OllamaManager``).
"""

from .backends.ollama_backend import (  # noqa: F401
    OllamaManager,
    _PsCacheLog,
    _is_ollama_client_transient_error,
    _is_ps_client_transient_error,
)

__all__ = [
    "OllamaManager",
    "_PsCacheLog",
    "_is_ollama_client_transient_error",
    "_is_ps_client_transient_error",
]