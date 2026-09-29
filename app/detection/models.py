"""
NexIDS Detection Models
=======================
Shared data structures produced by the Detection Engine.

``DetectionEvent`` is the canonical output of every detection module.
It represents an *observation* — not a confirmed attack.  The Alert Engine
(Phase 4) is responsible for turning DetectionEvents into prioritised Alerts.

Design principles
-----------------
* Plain dataclass — JSON-serialisable via ``asdict()``.
* All fields have sensible defaults so modules only need to fill what they know.
* ``confidence`` is a float in [0.0, 1.0] expressing how strongly the
  detector believes the pattern is significant.  It is NOT a probability of
  an attack; it is the detector's own internal certainty score.
* ``evidence`` is a free-form dict so each detector can attach the specific
  observable data that triggered the event.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class DetectionEvent:
    """A structured observation produced by a NexIDS detection module.

    Attributes
    ----------
    timestamp:
        Unix epoch (seconds) when the event was generated.
    detection_type:
        Human-readable category, e.g. ``"Potential Port Scan"``.
    source:
        Source IP address (or MAC for ARP events) if known.
    destination:
        Destination IP address if known; ``None`` when not applicable.
    protocol:
        Network protocol involved (``"TCP"``, ``"UDP"``, ``"ICMP"``, ``"ARP"``…).
    evidence:
        Detector-specific dict of observable facts that triggered the event.
        Examples: ``{"distinct_ports": 22, "ports": [22,80,443,...]}``.
    description:
        Short, plain-English explanation of what was observed.
    confidence:
        Detector confidence score in [0.0 – 1.0].
        0.0 = very uncertain / borderline threshold.
        1.0 = strong, unambiguous signal.
    detector:
        Name of the module that produced this event (set automatically).
    """

    detection_type: str
    source: str | None = None
    destination: str | None = None
    protocol: str = "UNKNOWN"
    evidence: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    confidence: float = 0.5
    detector: str = "unknown"
    timestamp: float = field(default_factory=time.time)

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict representation."""
        return asdict(self)

    def __post_init__(self) -> None:
        # Clamp confidence to valid range
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
