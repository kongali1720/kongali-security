"""
Kongali Security Core
=====================

Core components for the Kongali Security framework.

This package provides:

- SecurityEngine
- SecurityModule
- SecurityResult
"""

from kongali_security.core.engine import (
    ENGINE_VERSION,
    SecurityEngine,
    SecurityModule,
    SecurityResult,
)

__all__ = [
    "ENGINE_VERSION",
    "SecurityEngine",
    "SecurityModule",
    "SecurityResult",
]
