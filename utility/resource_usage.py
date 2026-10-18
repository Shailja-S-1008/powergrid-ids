"""Lightweight resource profiling used by every algorithm script.

``ResourceProfiler`` is a context manager that measures, for the enclosed block:
wall time (nanoseconds), peak total process RAM, and CPU utilisation
(average and peak, as a percentage of the whole machine, including children).
"""
import os
import time
import threading
import numpy as np
import psutil

# The process being profiled.
PROC = psutil.Process(os.getpid())


class PeakRSS:
    """Monitor peak RSS memory in a background thread."""

    def __init__(self, interval=0.05):
        self.interval = interval
        self.max_rss = 0
        self._stop = threading.Event()
        self._t = None

    def _run(self):
        while not self._stop.is_set():
            try:
                rss = PROC.memory_info().rss
                if rss > self.max_rss:
                    self.max_rss = rss
            except psutil.NoSuchProcess:
                break
            time.sleep(self.interval)

    def __enter__(self):
        try:
            self.max_rss = PROC.memory_info().rss
        except psutil.NoSuchProcess:
            self.max_rss = 0
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._stop.set()
        self._t.join()


class CpuMonitor:
    """Continuously sample process CPU% (optionally including children)."""

    def __init__(self, interval=0.01, include_children=False):
        self.interval = interval
        self.include_children = include_children
        self.samples = []
        self._stop = False
        self._thread = None
        self._proc = psutil.Process(os.getpid())

    def __enter__(self):
        try:
            self._proc.cpu_percent(interval=None)
            if self.include_children:
                for ch in self._proc.children(recursive=True):
                    ch.cpu_percent(interval=None)
        except psutil.NoSuchProcess:
            pass

        self.samples = []
        self._stop = False

        def _run():
            time.sleep(self.interval)
            while not self._stop:
                try:
                    total = float(self._proc.cpu_percent(interval=None))
                    if self.include_children:
                        for ch in self._proc.children(recursive=True):
                            try:
                                total += float(ch.cpu_percent(interval=None))
                            except psutil.NoSuchProcess:
                                pass
                    self.samples.append(total)
                except psutil.NoSuchProcess:
                    break
                time.sleep(self.interval)

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        time.sleep(self.interval)
        self._stop = True
        self._thread.join()

    def avg(self):
        return float(np.mean(self.samples)) if self.samples else 0.0

    def peak(self):
        return float(np.max(self.samples)) if self.samples else 0.0


class ResourceProfiler:
    """Profile wall time (ns), peak total RAM, and CPU% for a code block."""

    def __init__(self, interval=0.01):
        self.interval = interval
        self.proc = psutil.Process(os.getpid())
        self.n_cores = psutil.cpu_count(logical=True) or 1

        self.wall_nanoseconds = 0
        self.wall_seconds = 0.0
        self.cpu_avg_machine_pct = 0.0
        self.cpu_peak_machine_pct = 0.0
        self.peak_ram_mb = 0.0

    def __enter__(self):
        self.rss_mon = PeakRSS(self.interval)
        self.cpu_mon = CpuMonitor(self.interval, include_children=True)
        self.rss_mon.__enter__()
        self.cpu_mon.__enter__()

        self.t0_ns = time.perf_counter_ns()
        try:
            self.cpu_time0 = self.proc.cpu_times().user + self.proc.cpu_times().system
            self.cpu_time0 += sum(
                (ch.cpu_times().user + ch.cpu_times().system)
                for ch in self.proc.children(recursive=True)
            )
        except psutil.NoSuchProcess:
            self.cpu_time0 = 0
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.t1_ns = time.perf_counter_ns()
        try:
            self.cpu_time1 = self.proc.cpu_times().user + self.proc.cpu_times().system
            self.cpu_time1 += sum(
                (ch.cpu_times().user + ch.cpu_times().system)
                for ch in self.proc.children(recursive=True)
            )
        except psutil.NoSuchProcess:
            self.cpu_time1 = self.cpu_time0

        self.rss_mon.__exit__(None, None, None)
        self.cpu_mon.__exit__(None, None, None)

        self.wall_nanoseconds = max(1, self.t1_ns - self.t0_ns)
        self.wall_seconds = self.wall_nanoseconds / 1_000_000_000.0

        proc_cpu_seconds = max(0.0, self.cpu_time1 - self.cpu_time0)
        self.cpu_avg_machine_pct = (
            proc_cpu_seconds / (self.wall_seconds * self.n_cores)) * 100.0
        peak_cpu_percent = self.cpu_mon.peak() if self.cpu_mon.samples else 0.0
        self.cpu_peak_machine_pct = peak_cpu_percent / self.n_cores

        self.cpu_avg_machine_pct = round(max(0.0, min(100.0, self.cpu_avg_machine_pct)), 3)
        self.cpu_peak_machine_pct = round(max(0.0, min(100.0, self.cpu_peak_machine_pct)), 3)
        self.peak_ram_mb = round(self.rss_mon.max_rss / (1024 ** 2), 2)
