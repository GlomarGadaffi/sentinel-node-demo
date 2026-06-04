"""
correlation — Composite salience engine and state machine for SENTINEL-NODE.

Public exports
--------------
SalienceEngine
    Computes S(t) = W_a * T_d(t) + A_p(t) + M_d(t) from a stream of
    ThreatIndicator records and detects mode-crossing events.

SentinelStateMachine
    Full LISTENING ↔ DEFENDING state machine with cooldown, hysteresis,
    retrospective false-positive tracking, and failure-flag propagation.

agency_db helpers
    get_agency_weight, is_surveillance_icao, get_site_centroid —
    static lookup functions for the seed agency/ICAO database.

Failure-mode constants (from salience module)
    FALSE_POSITIVE_DENSE_CIVILIAN
    FALSE_POSITIVE_AVIATION_COMMERCIAL
    FALSE_NEGATIVE_SUPPRESSED_MESH
"""

from correlation.agency_db import (
    AGENCY_WEIGHTS,
    KNOWN_SITE_IDS,
    SURVEILLANCE_ICAO_PREFIXES,
    get_agency_weight,
    get_site_centroid,
    is_surveillance_icao,
)
from correlation.salience import (
    FALSE_NEGATIVE_SUPPRESSED_MESH,
    FALSE_POSITIVE_AVIATION_COMMERCIAL,
    FALSE_POSITIVE_DENSE_CIVILIAN,
    SalienceEngine,
)
from correlation.state_machine import (
    STATE_DEFENDING,
    STATE_LISTENING,
    SentinelStateMachine,
)

__all__ = [
    # Engine and state machine
    "SalienceEngine",
    "SentinelStateMachine",
    # State constants
    "STATE_LISTENING",
    "STATE_DEFENDING",
    # Failure-mode constants
    "FALSE_POSITIVE_DENSE_CIVILIAN",
    "FALSE_POSITIVE_AVIATION_COMMERCIAL",
    "FALSE_NEGATIVE_SUPPRESSED_MESH",
    # Agency DB helpers
    "get_agency_weight",
    "is_surveillance_icao",
    "get_site_centroid",
    # Agency DB data
    "AGENCY_WEIGHTS",
    "SURVEILLANCE_ICAO_PREFIXES",
    "KNOWN_SITE_IDS",
]
