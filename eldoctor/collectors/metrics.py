"""System metrics - the original El Doctor collector, plus rates."""
from __future__ import annotations

import csv
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import psutil

CSV_HEADER = ["timestamp", "cpu_usage", "used_memory_mb", "total_memory_mb", "used_disk_gb",
              "total_disk_gb", "incoming_traffic", "outgoing_traffic"]


def _disk_root() -> str:
    return os.environ.get("SystemDrive", "C:") + "\\" if os.name == "nt" else "/"


class MetricsCollector:
    def __init__(self, csv_path: Optional[Path] = None) -> None:
        self.csv_path = csv_path
        self._last_net = None
        self._last_ts = None
        psutil.cpu_percent(None)  # prime

    def collect(self) -> Dict[str, Any]:
        now = time.time()
        cpu = psutil.cpu_percent(None)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage(_disk_root())
        net = psutil.net_io_counters()
        rx_rate = tx_rate = 0.0
        if self._last_net is not None and self._last_ts:
            dt = max(now - self._last_ts, 1e-6)
            rx_rate = (net.bytes_recv - self._last_net.bytes_recv) / dt
            tx_rate = (net.bytes_sent - self._last_net.bytes_sent) / dt
        self._last_net, self._last_ts = net, now
        try:
            load = os.getloadavg()
        except (AttributeError, OSError):
            load = (0.0, 0.0, 0.0)
        return {
            "timestamp": datetime.now(),
            "cpu_usage": cpu,
            "per_cpu": psutil.cpu_percent(percpu=True),
            "used_memory": mem.used / (1024 ** 2),
            "total_memory": mem.total / (1024 ** 2),
            "memory_percent": mem.percent,
            "used_disk": disk.used / (1024 ** 3),
            "total_disk": disk.total / (1024 ** 3),
            "disk_percent": disk.percent,
            "incoming_traffic": net.bytes_recv,
            "outgoing_traffic": net.bytes_sent,
            "rx_rate": rx_rate,
            "tx_rate": tx_rate,
            "load": load,
            "process_count": len(psutil.pids()),
        }

    def log_csv(self, m: Dict[str, Any]) -> None:
        if not self.csv_path:
            return
        new = not self.csv_path.exists()
        with open(self.csv_path, "a", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            if new:
                w.writerow(CSV_HEADER)
            w.writerow([m["timestamp"], m["cpu_usage"], round(m["used_memory"], 2), round(m["total_memory"], 2),
                        round(m["used_disk"], 3), round(m["total_disk"], 3), m["incoming_traffic"],
                        m["outgoing_traffic"]])
