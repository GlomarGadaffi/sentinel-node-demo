"""
agency_db.py — Static seed database of agency weights and ICAO surveillance prefixes.

SENTINEL-NODE synthetic policy demonstration platform.
All data is fictional and used solely to demonstrate system behavior
under simulated enforcement pressure for policymaker education.
"""

from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Agency risk weights
# Keys are talkgroup subfleet prefix patterns.  The weight reflects how much
# additional salience each additional indicator from that subfleet adds to
# the composite score.  Values were chosen to produce analytically tractable
# output — they are not empirically derived from real operational data.
# ---------------------------------------------------------------------------
AGENCY_WEIGHTS: Dict[str, float] = {
    # Municipal first-responders: very low surveillance risk
    "municipal_fire":           0.05,
    "municipal_ems":            0.05,
    "municipal_public_works":   0.03,
    "municipal_transit":        0.04,

    # Law enforcement — routine patrol vs. tactical escalation
    "municipal_police_routine": 0.20,
    "municipal_police_tactical": 0.55,
    "state_patrol_routine":     0.15,
    "state_patrol_tactical":    0.60,
    "state_investigation":      0.40,

    # Federal / inter-agency
    "federal_routine":          0.50,
    "federal_tactical":         0.90,
    "federal_air_surveillance": 0.85,
    "joint_task_force":         0.80,

    # Unknown / encrypted — treated with elevated caution
    "unknown_encrypted":        0.45,
    "unknown_unidentified":     0.30,
    "interop_patch":            0.25,
}

# Default weight returned when no prefix matches.
_DEFAULT_WEIGHT = 0.10


# ---------------------------------------------------------------------------
# Fictional ICAO hex prefix blocks representing federal aviation assets.
# These are four-character prefixes applied to 6-character ICAO hex addresses.
# The blocks are invented and do not correspond to any real aircraft registry.
# Real federal aviation surveillance assets do not use these prefixes.
# ---------------------------------------------------------------------------
SURVEILLANCE_ICAO_PREFIXES: List[str] = [
    # Fictional DOJ / FBI surveillance aviation block (invented)
    "A7F0",
    "A7F1",
    "A7F2",
    "A7F3",
    # Fictional DHS / CBP block (invented)
    "AC40",
    "AC41",
    "AC42",
    # Fictional DEA aviation block (invented)
    "B3D0",
    "B3D1",
    # Fictional inter-agency task force block (invented)
    "C1E8",
    "C1E9",
    # Fictional state-level surveillance aviation block (invented)
    "D2A5",
    "D2A6",
]


# ---------------------------------------------------------------------------
# Known trunked-system site IDs mapped to approximate geographic centroids.
# Coordinates are fictional and placed in the Minneapolis–Saint Paul metro
# area for plausibility.  They do not represent real tower locations.
# ---------------------------------------------------------------------------
KNOWN_SITE_IDS: Dict[str, dict] = {
    "SITE_001": {
        "label": "Downtown Minneapolis (fictional)",
        "lat": 44.9778,
        "lon": -93.2650,
        "coverage_radius_km": 8.0,
    },
    "SITE_002": {
        "label": "Saint Paul Capitol Area (fictional)",
        "lat": 44.9537,
        "lon": -93.0900,
        "coverage_radius_km": 7.5,
    },
    "SITE_003": {
        "label": "North Minneapolis (fictional)",
        "lat": 45.0122,
        "lon": -93.2930,
        "coverage_radius_km": 6.0,
    },
    "SITE_004": {
        "label": "Southwest Minneapolis (fictional)",
        "lat": 44.9200,
        "lon": -93.3100,
        "coverage_radius_km": 6.5,
    },
    "SITE_005": {
        "label": "Bloomington / MSP Airport area (fictional)",
        "lat": 44.8810,
        "lon": -93.2218,
        "coverage_radius_km": 10.0,
    },
    "SITE_006": {
        "label": "Brooklyn Park (fictional)",
        "lat": 45.0930,
        "lon": -93.3560,
        "coverage_radius_km": 7.0,
    },
    "SITE_007": {
        "label": "East Saint Paul (fictional)",
        "lat": 44.9580,
        "lon": -93.0100,
        "coverage_radius_km": 6.0,
    },
}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def get_agency_weight(subfleet_prefix: str) -> float:
    """Return the risk weight for a talkgroup subfleet prefix.

    Matching is hierarchical: exact match first, then prefix containment
    (the supplied string is checked as a substring of each key and vice
    versa), finally the default is returned.  This produces sensible
    behaviour when callers pass partial or mangled prefix strings.

    Parameters
    ----------
    subfleet_prefix:
        A string identifying the talkgroup subfleet, e.g.
        ``"state_patrol_tactical"`` or ``"federal"``.

    Returns
    -------
    float
        Risk weight in [0.0, 1.0].
    """
    if not subfleet_prefix:
        return _DEFAULT_WEIGHT

    normalized = subfleet_prefix.strip().lower()

    # 1. Exact match
    if normalized in AGENCY_WEIGHTS:
        return AGENCY_WEIGHTS[normalized]

    # 2. The caller's string is a prefix of a known key  (e.g. "federal" → "federal_tactical")
    #    Return the maximum weight among all matching keys (worst-case assumption).
    prefix_matches = [
        w for key, w in AGENCY_WEIGHTS.items() if key.startswith(normalized)
    ]
    if prefix_matches:
        return max(prefix_matches)

    # 3. A known key is a prefix of the caller's string (e.g. "state_patrol_tactical_alpha")
    key_matches = [
        w for key, w in AGENCY_WEIGHTS.items() if normalized.startswith(key)
    ]
    if key_matches:
        return max(key_matches)

    # 4. Substring containment — last resort fuzzy pass
    substring_matches = [
        w for key, w in AGENCY_WEIGHTS.items()
        if key in normalized or normalized in key
    ]
    if substring_matches:
        return max(substring_matches)

    return _DEFAULT_WEIGHT


def is_surveillance_icao(icao_hex: str) -> bool:
    """Return True if the ICAO hex address belongs to a fictional surveillance prefix block.

    Parameters
    ----------
    icao_hex:
        6-character hexadecimal ICAO address string (case-insensitive).

    Returns
    -------
    bool
    """
    if not icao_hex or len(icao_hex) < 4:
        return False

    prefix = icao_hex.strip().upper()[:4]
    return prefix in SURVEILLANCE_ICAO_PREFIXES


def get_site_centroid(site_id: str) -> Optional[dict]:
    """Return the geographic centroid dict for a known site ID, or None."""
    return KNOWN_SITE_IDS.get(site_id)
