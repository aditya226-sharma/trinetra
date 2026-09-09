"""Flow collector — ingests NetFlow/IPFIX-style records or replays a dataset.

Two input modes:

* ``replay`` — stream JSONL flow records from a file (public dataset exports
  like CIC-IDS2017 are typically converted to JSONL/CSV before replay).
* ``push`` — accept pre-built flow dicts to be emitted as raw records.

Every record is emitted as a raw UES "netflow" line so the pipeline treats it
exactly like any other source — raw preserved, normalized, analyzed.
"""

from __future__ import annotations

import json
from itertools import islice
from pathlib import Path
from typing import Dict, Iterator, List, Optional

Line = tuple[str, str, str, str]


class FlowCollector:
    def __init__(self, replay_path: Optional[str] = None,
                 client_id: str = "flow-sensor-1") -> None:
        self.replay_path = Path(replay_path) if replay_path else None
        self.client_id = client_id

    def iterate(self, stagger_seconds: float = 0.0) -> Iterator[Line]:
        """Yield raw flow record strings from the replay dataset."""
        if self.replay_path is None:
            raise ValueError("FlowCollector needs a replay_path to iterate.")
        with open(self.replay_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                yield line, "netflow", self.client_id, ""

    def emit(self, record: Dict[str, object]) -> Line:
        """Push a structured flow dict as a raw record line."""
        return json.dumps(record, sort_keys=True), "netflow", self.client_id, ""


def load_flows(path: str | Path, limit: Optional[int] = None) -> List[Dict]:
    """Load replay dataset rows as dicts (used by Module A / tests)."""
    rows: List[Dict] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                rows.append(json.loads(line))
            else:
                parts = line.split("\t")
                if len(parts) >= 8:
                    rows.append({
                        "ts": parts[0], "src": parts[1], "dst": parts[2],
                        "proto": parts[3], "sport": parts[4], "dport": parts[5],
                        "pkts": parts[6], "bytes": parts[7],
                        "flags": parts[8] if len(parts) > 8 else "",
                    })
            if limit and len(rows) >= limit:
                break
    return rows