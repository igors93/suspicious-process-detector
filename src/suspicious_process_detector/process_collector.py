"""
Process collection module.

This module is responsible only for collecting process data from the operating
system. It does not decide whether a process is suspicious.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from typing import TypeVar

import psutil

from suspicious_process_detector.models import ProcessInfo


T = TypeVar("T")


class ProcessCollector:
    """
    Collects running process information from the operating system.

    The collector uses psutil and handles common permission errors gracefully.
    """

    def __init__(self, cpu_sample_interval: float = 0.1) -> None:
        """
        Initialize the process collector.

        Args:
            cpu_sample_interval: Small delay used to improve CPU usage sampling.
        """
        self.cpu_sample_interval = cpu_sample_interval

    def collect(self) -> list[ProcessInfo]:
        """
        Collect all accessible running processes.

        Returns:
            list[ProcessInfo]: List of collected process information.
        """
        self._warm_up_cpu_counters()
        time.sleep(self.cpu_sample_interval)

        processes: list[ProcessInfo] = []

        for process in psutil.process_iter():
            process_info = self._safe_collect_process(process)

            if process_info is not None:
                processes.append(process_info)

        return processes

    def _warm_up_cpu_counters(self) -> None:
        """
        Warm up psutil CPU counters.

        psutil may return 0.0 on the first CPU usage call. Calling it once
        before collecting data improves the accuracy of the next reading.
        """
        for process in psutil.process_iter():
            self._safe_call(lambda: process.cpu_percent(interval=None))

    def _safe_collect_process(self, process: psutil.Process) -> ProcessInfo | None:
        """
        Safely collect data from a single process.

        Args:
            process: psutil process instance.

        Returns:
            ProcessInfo | None: Process info if the process still exists.
        """
        if not self._process_exists(process):
            return None

        command_line_parts = self._safe_call(process.cmdline, default=[]) or []
        created_at_raw = self._safe_call(process.create_time)
        cpu_percent = self._safe_call(
            lambda: process.cpu_percent(interval=None),
            default=0.0,
        )
        memory_percent = self._safe_call(process.memory_percent, default=0.0)

        return ProcessInfo(
            pid=process.pid,
            name=self._safe_call(process.name, default="unknown") or "unknown",
            username=self._safe_call(process.username),
            executable_path=self._safe_call(process.exe),
            command_line=self._format_command_line(command_line_parts),
            cpu_percent=round(cpu_percent or 0.0, 2),
            memory_percent=round(memory_percent or 0.0, 2),
            ppid=self._safe_call(process.ppid),
            parent_name=self._get_parent_name(process),
            status=self._safe_call(process.status),
            created_at=self._format_timestamp(created_at_raw),
        )

    @staticmethod
    def _process_exists(process: psutil.Process) -> bool:
        """
        Check if a process still exists.

        Args:
            process: psutil process instance.

        Returns:
            bool: True if process exists, otherwise False.
        """
        try:
            return process.is_running()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return False

    @staticmethod
    def _safe_call(func: Callable[[], T], default: T | None = None) -> T | None:
        """
        Safely call a psutil function.

        Args:
            func: Function to call.
            default: Value returned when access fails.

        Returns:
            T | None: Function result or default value.
        """
        try:
            return func()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return default

    def _get_parent_name(self, process: psutil.Process) -> str | None:
        """
        Safely get the parent process name.

        Args:
            process: psutil process instance.

        Returns:
            str | None: Parent process name if available.
        """
        parent = self._safe_call(process.parent)

        if parent is None:
            return None

        return self._safe_call(parent.name)

    @staticmethod
    def _format_command_line(command_line_parts: Iterable[str]) -> str:
        """
        Convert command-line parts into a readable string.

        Args:
            command_line_parts: Iterable with command-line arguments.

        Returns:
            str: Joined command line.
        """
        return " ".join(command_line_parts)

    @staticmethod
    def _format_timestamp(timestamp: float | None) -> str | None:
        """
        Convert a UNIX timestamp to UTC ISO 8601 format.

        Args:
            timestamp: UNIX timestamp.

        Returns:
            str | None: UTC ISO timestamp or None.
        """
        if timestamp is None:
            return None

        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()