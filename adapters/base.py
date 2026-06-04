from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
import hashlib


@dataclass
class GeoPoint:
    lat: Optional[float] = None
    lon: Optional[float] = None
    accuracy_m: Optional[float] = None
    source: str = "unknown"


@dataclass
class ThreatIndicator:
    """A single normalized signal event entering the salience engine."""
    event_id: UUID
    timestamp: datetime
    channel: str              # EDACS | ADS_B | MESHTASTIC
    source_tool: str
    latitude: Optional[float]
    longitude: Optional[float]
    primary_id: Optional[str]
    secondary_ids: List[str]
    metadata: Dict[str, Any]
    tags: List[str]
    raw_weight: float = 1.0   # pre-loaded agency weight override


@dataclass
class SalienceSnapshot:
    """Point-in-time salience score with decomposed components for analysis."""
    snapshot_id: UUID
    timestamp: datetime
    score: float              # S(t) composite
    trunking_term: float      # W_a * T_d(t)
    aviation_term: float      # A_p(t)
    mesh_term: float          # M_d(t)
    threshold: float
    mode: str                 # LISTENING | DEFENDING
    trigger_reason: Optional[str] = None


@dataclass
class ModeTransition:
    """Records every LISTENING ↔ DEFENDING state change with cause and failure notes."""
    transition_id: UUID
    timestamp: datetime
    from_mode: str
    to_mode: str
    salience_at_transition: float
    trigger_snapshot_id: Optional[UUID]
    failure_flags: List[str] = field(default_factory=list)
    # Populated when a transition is retrospectively assessed as a false positive
    retrospective_fp: bool = False
    fp_reason: Optional[str] = None


@dataclass
class AlertRecord:
    """A shroud-speak alert packet — signed, TTL-bounded, Tor-addressed."""
    alert_id: UUID
    timestamp: datetime
    triggering_snapshot_id: UUID
    payload_json: str         # Ed25519-signed JSON body
    onion_address: str        # ephemeral — rotates every N minutes
    ttl_seconds: int = 300
    dispatched: bool = False
    dispatch_error: Optional[str] = None
