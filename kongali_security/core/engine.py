"""
Kongali Security Core Engine
============================

Core execution engine for the Kongali Security framework.

This module provides the central SecurityEngine class used to:

- Register security analysis modules
- Execute analysis modules
- Normalize analysis results
- Track execution metadata
- Handle module errors safely
- Return structured security results

Version:
    0.1.0

Project:
    https://github.com/kongali1720/kongali-security
"""

from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


ENGINE_VERSION = "0.1.0"


@dataclass
class SecurityResult:
    """
    Standardized result returned by the Kongali Security Engine.

    Attributes:
        tool:
            Name of the security framework.

        version:
            Engine version.

        module:
            Name of the module that produced the result.

        timestamp:
            UTC timestamp when the analysis started.

        input:
            Original input provided to the module.

        input_type:
            Type of analyzed input.

        status:
            Execution status.

        risk:
            Risk classification.

        confidence:
            Confidence score between 0.0 and 1.0.

        findings:
            List of detected security findings.

        metadata:
            Additional module-specific information.

        execution_time_ms:
            Module execution time in milliseconds.

        error:
            Error information when execution fails.
    """

    tool: str = "kongali-security"
    version: str = ENGINE_VERSION
    module: str = ""
    timestamp: str = ""
    input: Any = None
    input_type: str = "unknown"
    status: str = "success"
    risk: str = "unknown"
    confidence: float = 0.0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    execution_time_ms: float = 0.0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the security result into a JSON-compatible dictionary.

        Returns:
            Dictionary representation of the security result.
        """

        return {
            "tool": self.tool,
            "version": self.version,
            "module": self.module,
            "timestamp": self.timestamp,
            "input": self.input,
            "input_type": self.input_type,
            "status": self.status,
            "risk": self.risk,
            "confidence": self.confidence,
            "findings": self.findings,
            "metadata": self.metadata,
            "execution_time_ms": self.execution_time_ms,
            "error": self.error,
        }


@dataclass
class SecurityModule:
    """
    Represents a registered security analysis module.

    Attributes:
        name:
            Unique module name.

        description:
            Human-readable module description.

        handler:
            Callable function responsible for performing the analysis.

        enabled:
            Whether the module is enabled.
    """

    name: str
    description: str
    handler: Callable[..., Any]
    enabled: bool = True


class SecurityEngine:
    """
    Central execution engine for Kongali Security.

    The SecurityEngine provides a modular architecture where individual
    security analysis modules can be registered and executed.

    Example:

        engine = SecurityEngine()

        engine.register_module(
            name="example",
            description="Example security module",
            handler=my_handler,
        )

        result = engine.run(
            module_name="example",
            input_data="example.com",
        )
    """

    def __init__(self) -> None:
        """Initialize the Kongali Security Engine."""

        self.name = "kongali-security"
        self.version = ENGINE_VERSION

        self._modules: Dict[str, SecurityModule] = {}

    @property
    def modules(self) -> Dict[str, SecurityModule]:
        """
        Return all registered security modules.

        Returns:
            Dictionary containing registered modules.
        """

        return self._modules.copy()

    def register_module(
        self,
        name: str,
        description: str,
        handler: Callable[..., Any],
        enabled: bool = True,
    ) -> None:
        """
        Register a security analysis module.

        Args:
            name:
                Unique module name.

            description:
                Human-readable module description.

            handler:
                Callable responsible for performing the analysis.

            enabled:
                Whether the module should be enabled.

        Raises:
            ValueError:
                If the module name is empty or already registered.

            TypeError:
                If the handler is not callable.
        """

        normalized_name = name.strip().lower()

        if not normalized_name:
            raise ValueError("Module name cannot be empty.")

        if normalized_name in self._modules:
            raise ValueError(
                f"Security module '{normalized_name}' is already registered."
            )

        if not callable(handler):
            raise TypeError(
                f"Handler for module '{normalized_name}' must be callable."
            )

        self._modules[normalized_name] = SecurityModule(
            name=normalized_name,
            description=description.strip(),
            handler=handler,
            enabled=enabled,
        )

    def unregister_module(self, name: str) -> None:
        """
        Remove a registered security module.

        Args:
            name:
                Name of the module to remove.

        Raises:
            KeyError:
                If the module does not exist.
        """

        normalized_name = name.strip().lower()

        if normalized_name not in self._modules:
            raise KeyError(
                f"Security module '{normalized_name}' is not registered."
            )

        del self._modules[normalized_name]

    def enable_module(self, name: str) -> None:
        """
        Enable a registered security module.

        Args:
            name:
                Name of the module to enable.
        """

        module = self._get_module(name)
        module.enabled = True

    def disable_module(self, name: str) -> None:
        """
        Disable a registered security module.

        Args:
            name:
                Name of the module to disable.
        """

        module = self._get_module(name)
        module.enabled = False

    def get_module(self, name: str) -> SecurityModule:
        """
        Retrieve a registered security module.

        Args:
            name:
                Name of the module.

        Returns:
            Registered SecurityModule instance.
        """

        return self._get_module(name)

    def list_modules(self) -> List[Dict[str, Any]]:
        """
        Return a serializable list of registered modules.

        Returns:
            List containing module metadata.
        """

        return [
            {
                "name": module.name,
                "description": module.description,
                "enabled": module.enabled,
            }
            for module in self._modules.values()
        ]

    def run(
        self,
        module_name: str,
        input_data: Any,
        input_type: str = "unknown",
        **kwargs: Any,
    ) -> SecurityResult:
        """
        Execute a registered security analysis module.

        The module handler may return:

        1. A SecurityResult instance.
        2. A dictionary containing result data.
        3. Any other value, which will be stored as module metadata.

        Args:
            module_name:
                Name of the registered module.

            input_data:
                Data to analyze.

            input_type:
                Type of input being analyzed.

            **kwargs:
                Additional arguments passed to the module handler.

        Returns:
            Standardized SecurityResult.
        """

        module = self._get_module(module_name)

        timestamp = datetime.now(timezone.utc).isoformat()

        start_time = time.perf_counter()

        if not module.enabled:
            return SecurityResult(
                module=module.name,
                timestamp=timestamp,
                input=input_data,
                input_type=input_type,
                status="disabled",
                risk="unknown",
                confidence=0.0,
                metadata={
                    "message": (
                        f"Security module '{module.name}' is currently disabled."
                    )
                },
                execution_time_ms=0.0,
            )

        try:
            raw_result = module.handler(
                input_data=input_data,
                **kwargs,
            )

            execution_time_ms = (
                time.perf_counter() - start_time
            ) * 1000

            return self._normalize_result(
                module=module,
                input_data=input_data,
                input_type=input_type,
                timestamp=timestamp,
                raw_result=raw_result,
                execution_time_ms=execution_time_ms,
            )

        except Exception as exc:
            execution_time_ms = (
                time.perf_counter() - start_time
            ) * 1000

            return SecurityResult(
                module=module.name,
                timestamp=timestamp,
                input=input_data,
                input_type=input_type,
                status="error",
                risk="unknown",
                confidence=0.0,
                findings=[],
                metadata={
                    "exception_type": type(exc).__name__,
                    "traceback": traceback.format_exc(),
                },
                execution_time_ms=execution_time_ms,
                error=str(exc),
            )

    def run_all(
        self,
        input_data: Any,
        input_type: str = "unknown",
        **kwargs: Any,
    ) -> List[SecurityResult]:
        """
        Execute all enabled registered security modules.

        Args:
            input_data:
                Data to analyze.

            input_type:
                Type of input being analyzed.

            **kwargs:
                Additional arguments passed to each module.

        Returns:
            List of standardized SecurityResult objects.
        """

        results: List[SecurityResult] = []

        for module in self._modules.values():
            if not module.enabled:
                continue

            result = self.run(
                module_name=module.name,
                input_data=input_data,
                input_type=input_type,
                **kwargs,
            )

            results.append(result)

        return results

    def _get_module(self, name: str) -> SecurityModule:
        """
        Retrieve a module by normalized name.

        Args:
            name:
                Module name.

        Returns:
            SecurityModule instance.

        Raises:
            KeyError:
                If the module is not registered.
        """

        normalized_name = name.strip().lower()

        if normalized_name not in self._modules:
            available_modules = ", ".join(
                sorted(self._modules.keys())
            )

            if available_modules:
                message = (
                    f"Security module '{normalized_name}' is not registered. "
                    f"Available modules: {available_modules}"
                )
            else:
                message = (
                    f"Security module '{normalized_name}' is not registered. "
                    "No modules are currently available."
                )

            raise KeyError(message)

        return self._modules[normalized_name]

    def _normalize_result(
        self,
        module: SecurityModule,
        input_data: Any,
        input_type: str,
        timestamp: str,
        raw_result: Any,
        execution_time_ms: float,
    ) -> SecurityResult:
        """
        Normalize module output into SecurityResult.

        Args:
            module:
                Module that generated the result.

            input_data:
                Original analyzed input.

            input_type:
                Input classification.

            timestamp:
                Analysis timestamp.

            raw_result:
                Raw module output.

            execution_time_ms:
                Execution duration.

        Returns:
            Normalized SecurityResult.
        """

        if isinstance(raw_result, SecurityResult):
            raw_result.tool = self.name
            raw_result.version = self.version
            raw_result.module = module.name
            raw_result.timestamp = timestamp
            raw_result.input = input_data
            raw_result.input_type = input_type
            raw_result.execution_time_ms = execution_time_ms

            return raw_result

        if isinstance(raw_result, dict):
            findings = raw_result.get("findings", [])

            if not isinstance(findings, list):
                findings = [findings]

            metadata = raw_result.get("metadata", {})

            if not isinstance(metadata, dict):
                metadata = {
                    "module_metadata": metadata,
                }

            return SecurityResult(
                module=module.name,
                timestamp=timestamp,
                input=input_data,
                input_type=input_type,
                status=str(
                    raw_result.get(
                        "status",
                        "success",
                    )
                ),
                risk=str(
                    raw_result.get(
                        "risk",
                        "unknown",
                    )
                ),
                confidence=self._normalize_confidence(
                    raw_result.get(
                        "confidence",
                        0.0,
                    )
                ),
                findings=findings,
                metadata=metadata,
                execution_time_ms=execution_time_ms,
                error=raw_result.get("error"),
            )

        return SecurityResult(
            module=module.name,
            timestamp=timestamp,
            input=input_data,
            input_type=input_type,
            status="success",
            risk="unknown",
            confidence=0.0,
            findings=[],
            metadata={
                "result": raw_result,
            },
            execution_time_ms=execution_time_ms,
        )

    @staticmethod
    def _normalize_confidence(value: Any) -> float:
        """
        Normalize confidence value to a range between 0.0 and 1.0.

        Args:
            value:
                Confidence value.

        Returns:
            Float between 0.0 and 1.0.
        """

        try:
            confidence = float(value)
        except (TypeError, ValueError):
            return 0.0

        return max(
            0.0,
            min(
                1.0,
                confidence,
            ),
        )


__all__ = [
    "ENGINE_VERSION",
    "SecurityEngine",
    "SecurityModule",
    "SecurityResult",
]
