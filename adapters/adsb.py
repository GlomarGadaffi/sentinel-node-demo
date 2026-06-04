"""
Synthetic ADS-B DF17 aviation transponder adapter.

All data produced by this module is SYNTHETIC. No actual ADS-B receiver,
no 1090 MHz RF hardware, and no live airspace data are involved. This adapter
generates representative Mode-S extended squitter (DF17) traffic patterns
for policy demonstration purposes.

ADS-B DF17 frames are 112-bit Mode-S transmissions broadcast on 1090 MHz.
Each frame carries a 24-bit ICAO aircraft address (globally unique), a 5-bit
downlink format (DF=17 for ADS-B), and a 56-bit message payload whose
content is determined by the Type Code (TC) field. TC 9–18 encode airborne
position (barometric altitude + compact position report). TC 19 encodes
airborne velocity. TC 1–4 encode aircraft identification (callsign).

The "surveillance_pattern" scenario models persistent low-altitude orbit by
aircraft whose ICAO addresses fall within ICAO hex blocks historically
associated with US federal aviation assets. Tight orbital radius (<2 km),
declining ground distance to the node over successive frames, and altitudes
below 3000 ft AGL are the discriminating features evaluated by the aviation
term A_p(t) in the salience engine.

ICAO address block assignments referenced here are ILLUSTRATIVE for
demonstration purposes and do not represent authoritative FAA or ICAO
registration data.
"""

import math
import random
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from uuid import uuid4

from adapters.base import ThreatIndicator


# ---------------------------------------------------------------------------
# ICAO address block constants
# ---------------------------------------------------------------------------
# Real ICAO 24-bit addresses are allocated by block to national aviation
# authorities. The US block is 0xA00000–0xAFFFFF (prefix "A" in hex).
# Within that block, certain sub-ranges are informally associated with
# federal/government operators based on registration cross-references.
# The ranges below are illustrative — chosen to be structurally realistic
# without encoding any actual operational intelligence.

ICAO_SURVEILLANCE_PREFIXES = (
    "A000",   # FAA test aircraft / unregistered federal block (illustrative)
    "A001",   # Illustrative federal aviation sub-block
    "A002",   # Illustrative federal aviation sub-block
    "A003",   # Illustrative ISR-associated registration range
    "A004",   # Illustrative ISR-associated registration range
    "A005",   # Illustrative patrol aircraft sub-block
    "A900",   # Illustrative government fleet sub-block
    "A901",   # Illustrative government fleet sub-block
    "A902",   # Illustrative government fleet sub-block
    "ADF0",   # Illustrative DHS-associated range
    "ADF1",   # Illustrative DHS-associated range
    "AE00",   # Illustrative military-associated block
    "AE01",   # Illustrative military-associated block
)

# Realistic commercial airline ICAO blocks for overpass scenario
ICAO_COMMERCIAL_RANGES = (
    ("A80000", "A8FFFF"),   # Major US carrier block (illustrative)
    ("AB0000", "AB7FFF"),   # Regional carrier block (illustrative)
    ("AC0000", "ACFFFF"),   # Cargo carrier block (illustrative)
)

# Realistic callsign prefixes by operator type
COMMERCIAL_CALLSIGN_PREFIXES = ["AAL", "DAL", "UAL", "SWA", "SKW", "ENY", "ASQ", "PDT"]
SURVEILLANCE_CALLSIGN_PREFIXES = ["N", "MEDIC", "LAW", "EAGLE", "HAWK", "FALCON"]


def _random_surveillance_icao() -> str:
    prefix = random.choice(ICAO_SURVEILLANCE_PREFIXES)
    suffix_len = 6 - len(prefix)
    suffix = "".join(random.choice("0123456789ABCDEF") for _ in range(suffix_len))
    return (prefix + suffix).upper()


def _random_commercial_icao() -> str:
    lo_hex, hi_hex = random.choice(ICAO_COMMERCIAL_RANGES)
    lo = int(lo_hex, 16)
    hi = int(hi_hex, 16)
    val = random.randint(lo, hi)
    return f"{val:06X}"


def _random_commercial_callsign() -> str:
    prefix = random.choice(COMMERCIAL_CALLSIGN_PREFIXES)
    number = random.randint(100, 9999)
    return f"{prefix}{number}"


def _random_surveillance_callsign() -> str:
    prefix = random.choice(SURVEILLANCE_CALLSIGN_PREFIXES)
    number = random.randint(10, 99)
    return f"{prefix}{number}"


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres between two WGS-84 coordinates."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(math.radians(lat1))
        * math.cos(math.radians(lat2))
        * math.sin(dlon / 2) ** 2
    )
    return R * 2.0 * math.asin(math.sqrt(a))


def _bearing_offset(lat: float, lon: float, bearing_deg: float, dist_km: float):
    """Return (lat2, lon2) reached by travelling dist_km on a given bearing."""
    R = 6371.0
    d = dist_km / R
    b = math.radians(bearing_deg)
    lat1 = math.radians(lat)
    lon1 = math.radians(lon)
    lat2 = math.asin(
        math.sin(lat1) * math.cos(d)
        + math.cos(lat1) * math.sin(d) * math.cos(b)
    )
    lon2 = lon1 + math.atan2(
        math.sin(b) * math.sin(d) * math.cos(lat1),
        math.cos(d) - math.sin(lat1) * math.sin(lat2),
    )
    return math.degrees(lat2), math.degrees(lon2)


class ADSBSyntheticAdapter:
    """
    Generates synthetic ADS-B DF17 transponder scenarios as lists of
    ThreatIndicator objects.

    Three scenarios are supported:

    "no_aircraft"
        Empty airspace. Returns an empty list. Represents a baseline
        measurement period with no aviation signal contribution.

    "commercial_overpass"
        2–5 airline-type aircraft at cruise altitude (28 000–39 000 ft),
        high ground speed (420–540 kts), large distance from the node
        (25–120 km). ICAO addresses outside surveillance prefix blocks.
        These produce no meaningful A_p(t) contribution.

    "surveillance_pattern"
        1–3 aircraft with ICAO addresses in the surveillance prefix list,
        orbiting a fixed point within 1.5 km of the node at low altitude
        (800–2800 ft AGL), low-to-moderate speed (90–180 kts). Successive
        frames show decreasing distance (inbound spiral) followed by a
        tight circular pattern. orbit_pattern=True and
        icao_surveillance_flag=True are set, driving high A_p(t) values.
    """

    channel    = "ADS_B"
    source_tool = "ADSBSynthetic"

    def generate_scenario(
        self,
        scenario: str,
        node_lat: float,
        node_lon: float,
    ) -> List[ThreatIndicator]:
        if scenario == "no_aircraft":
            return []
        elif scenario == "commercial_overpass":
            return self._commercial_overpass(node_lat, node_lon)
        elif scenario == "surveillance_pattern":
            return self._surveillance_pattern(node_lat, node_lon)
        else:
            raise ValueError(
                f"Unknown scenario '{scenario}'. "
                "Valid scenarios: 'no_aircraft', 'commercial_overpass', 'surveillance_pattern'."
            )

    # ------------------------------------------------------------------
    # Scenario generators
    # ------------------------------------------------------------------

    def _commercial_overpass(
        self, node_lat: float, node_lon: float
    ) -> List[ThreatIndicator]:
        count = random.randint(2, 5)
        base_time = datetime.now(timezone.utc)
        indicators = []

        for i in range(count):
            icao = _random_commercial_icao()
            callsign = _random_commercial_callsign()
            altitude_ft = random.randint(28000, 39000)
            velocity_kts = random.randint(420, 540)

            # Aircraft is far from node, transiting overhead
            bearing = random.uniform(0, 360)
            dist_km = random.uniform(25.0, 120.0)
            ac_lat, ac_lon = _bearing_offset(node_lat, node_lon, bearing, dist_km)
            actual_dist = _haversine_km(node_lat, node_lon, ac_lat, ac_lon)

            ts = base_time + timedelta(seconds=random.uniform(0, 300))

            indicators.append(self._build_indicator(
                icao_hex=icao,
                callsign=callsign,
                altitude_ft=altitude_ft,
                velocity_kts=velocity_kts,
                ac_lat=ac_lat,
                ac_lon=ac_lon,
                distance_km=round(actual_dist, 3),
                orbit_pattern=False,
                icao_surveillance_flag=False,
                raw_weight=round(random.uniform(0.02, 0.08), 3),
                timestamp=ts,
                tags=["commercial", "overpass"],
            ))

        return indicators

    def _surveillance_pattern(
        self, node_lat: float, node_lon: float
    ) -> List[ThreatIndicator]:
        """
        Generate 1–3 surveillance aircraft in a tight orbit near the node.

        Each aircraft contributes multiple positional frames representing
        successive ADS-B broadcasts (~1 per second realistically; modelled
        here as discrete samples spanning a ~4-minute window). Orbit centre
        is placed 0.3–0.9 km from the node. Frames show decreasing approach
        distance then stabilization inside the orbit radius, consistent with
        a loiter pattern.
        """
        aircraft_count = random.randint(1, 3)
        base_time = datetime.now(timezone.utc)
        indicators = []

        for ac_idx in range(aircraft_count):
            icao = _random_surveillance_icao()
            callsign = _random_surveillance_callsign()
            altitude_ft = random.randint(800, 2800)
            velocity_kts = random.randint(90, 180)

            # Orbit centre: close to node
            orbit_bearing = random.uniform(0, 360)
            orbit_center_dist_km = random.uniform(0.3, 0.9)
            orbit_center_lat, orbit_center_lon = _bearing_offset(
                node_lat, node_lon, orbit_bearing, orbit_center_dist_km
            )
            orbit_radius_km = random.uniform(0.4, 1.2)

            # Generate 6–12 positional frames per aircraft
            frame_count = random.randint(6, 12)
            initial_approach_frames = frame_count // 3

            for f in range(frame_count):
                t_offset = f * random.uniform(18.0, 35.0)
                ts = base_time + timedelta(seconds=t_offset)

                if f < initial_approach_frames:
                    # Approaching: start farther, close to orbit center
                    approach_frac = f / max(initial_approach_frames - 1, 1)
                    dist_to_center = orbit_center_dist_km * (1.0 + (1.0 - approach_frac) * 3.0)
                    approach_bearing = orbit_bearing + 180.0 + random.uniform(-15, 15)
                    ac_lat, ac_lon = _bearing_offset(
                        orbit_center_lat, orbit_center_lon,
                        approach_bearing % 360, dist_to_center
                    )
                else:
                    # Orbiting: position on circumference, angle advances
                    orbit_frac = (f - initial_approach_frames) / max(frame_count - initial_approach_frames, 1)
                    orbit_angle = (orbit_bearing + orbit_frac * 360.0 + random.uniform(-8, 8)) % 360
                    radial_jitter = random.uniform(-0.05, 0.05)
                    ac_lat, ac_lon = _bearing_offset(
                        orbit_center_lat, orbit_center_lon,
                        orbit_angle, orbit_radius_km + radial_jitter
                    )

                distance_km = _haversine_km(node_lat, node_lon, ac_lat, ac_lon)

                is_orbiting = f >= initial_approach_frames
                is_surveillance = any(
                    icao.upper().startswith(p) for p in ICAO_SURVEILLANCE_PREFIXES
                )

                indicators.append(self._build_indicator(
                    icao_hex=icao,
                    callsign=callsign,
                    altitude_ft=altitude_ft + random.randint(-50, 50),
                    velocity_kts=velocity_kts + random.randint(-10, 10),
                    ac_lat=ac_lat,
                    ac_lon=ac_lon,
                    distance_km=round(distance_km, 3),
                    orbit_pattern=is_orbiting,
                    icao_surveillance_flag=is_surveillance,
                    raw_weight=round(random.uniform(0.70, 0.95), 3),
                    timestamp=ts,
                    tags=(
                        ["surveillance", "orbit", "low_altitude"]
                        if is_orbiting
                        else ["surveillance", "approach", "low_altitude"]
                    ),
                ))

        return indicators

    # ------------------------------------------------------------------
    # Internal builder
    # ------------------------------------------------------------------

    def _build_indicator(
        self,
        icao_hex: str,
        callsign: str,
        altitude_ft: int,
        velocity_kts: int,
        ac_lat: float,
        ac_lon: float,
        distance_km: float,
        orbit_pattern: bool,
        icao_surveillance_flag: bool,
        raw_weight: float,
        timestamp: datetime,
        tags: List[str],
    ) -> ThreatIndicator:

        secondary_ids = [f"callsign:{callsign}"]
        if icao_surveillance_flag:
            secondary_ids.append("icao_block:surveillance")

        return ThreatIndicator(
            event_id=uuid4(),
            timestamp=timestamp,
            channel=self.channel,
            source_tool=self.source_tool,
            latitude=ac_lat,
            longitude=ac_lon,
            primary_id=icao_hex.upper(),
            secondary_ids=secondary_ids,
            metadata={
                "icao_hex":              icao_hex.upper(),
                "callsign":              callsign,
                "altitude_ft":           altitude_ft,
                "velocity_kts":          velocity_kts,
                "aircraft_lat":          round(ac_lat, 6),
                "aircraft_lon":          round(ac_lon, 6),
                "distance_km":           distance_km,
                "orbit_pattern":         orbit_pattern,
                "icao_surveillance_flag": icao_surveillance_flag,
                "df":                    17,   # DF17 — ADS-B extended squitter
                "tc_position":           11,   # Type Code 11: airborne position
                "tc_velocity":           19,   # Type Code 19: airborne velocity
            },
            tags=tags,
            raw_weight=raw_weight,
        )
