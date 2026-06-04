"""
Synthetic CLIENT_MUTE passive Meshtastic frame adapter.

RECEIVE-ONLY. This adapter operates exclusively in CLIENT_MUTE mode.
There is NO transmit path in this module. The node does not send any
Meshtastic frames, does not respond to position broadcasts, does not
acknowledge received packets, and does not participate in mesh routing.
Any function that would write to a radio interface does not exist here.
CLIENT_MUTE is a Meshtastic firmware role that disables all transmission
while retaining the ability to decode frames received over the air.

All data produced by this module is SYNTHETIC. No actual Meshtastic
radio hardware (LoRa transceiver) or live mesh network is involved.

Meshtastic uses a LoRa PHY layer (typically 915 MHz in the US) with a
custom binary protocol framing each packet as a MeshPacket protobuf.
Relevant decoded fields for this adapter include:
  - from_node (4-byte node ID, displayed as !hex8 e.g. !a3f7c201)
  - hop_limit / hop_count: remaining hops vs original TTL
  - RSSI: received signal strength (dBm, typical range -60 to -140)
  - SNR: signal-to-noise ratio (dB, typical range +12 to -20)
  - portnum: application payload type (TEXT_MESSAGE, POSITION, NODEINFO, etc.)
  - decoded position: lat/lon if POSITION packet

Node IDs in this adapter use the !hex8 format standard to Meshtastic
(exclamation prefix, 8 hex characters representing the 32-bit node ID).

The "active_spotters" scenario models a detected threat pattern: a small
cluster of mobile nodes within 300m of the sentinel node, with node_profile
tags indicating surveillance-adjacent roles. Short distance + high RSSI +
mobile profile is the discriminating feature evaluated by the mesh term
M_d(t). The CLIENT_MUTE constraint means these nodes are observed but
cannot be confirmed to be monitoring this node specifically — this ambiguity
is a design limitation documented in the policy paper.
"""

import math
import random
import struct
from datetime import datetime, timezone, timedelta
from typing import List
from uuid import uuid4

from adapters.base import ThreatIndicator


# ---------------------------------------------------------------------------
# Node profile taxonomy
# ---------------------------------------------------------------------------
# These profile tags are inferred from the NODEINFO portnum payload's
# long_name/short_name fields, cross-referenced against hop count and RSSI
# to estimate mobility and proximity intent.

SPOTTER_PROFILES = [
    "spotter",
    "mobile",
    "tactical_civilian",
    "forward_obs",
    "relay_mobile",
    "field_op",
]

CIVILIAN_PROFILES = [
    "hiker",
    "ham_operator",
    "emergency_prep",
    "neighborhood_watch",
    "volunteer",
    "mesh_enthusiast",
    "trail_runner",
    "camper",
    "cyclist",
    "student",
    "maker",
    "offgrid_node",
    "festival_crew",
    "search_rescue_volunteer",
    "local_mesh",
]

# Meshtastic portnum constants (subset)
PORTNUM_TEXT_MESSAGE = "TEXT_MESSAGE_APP"
PORTNUM_POSITION     = "POSITION_APP"
PORTNUM_NODEINFO     = "NODEINFO_APP"
PORTNUM_TELEMETRY    = "TELEMETRY_APP"
PORTNUM_ROUTING      = "ROUTING_APP"

# Typical LoRa 915 MHz free-space path loss model coefficients
# Used to derive synthetic RSSI from distance
_FSPL_FREQ_MHZ  = 915.0
_FSPL_CONST     = 20 * math.log10(_FSPL_FREQ_MHZ) + 20 * math.log10(4 * math.pi / 3e8 * 1e6)


def _rssi_from_distance_m(distance_m: float, tx_power_dbm: float = 20.0) -> int:
    """
    Estimate received RSSI (dBm) from distance using free-space path loss.

    FSPL(d) = 20*log10(d) + 20*log10(f) + 20*log10(4*pi/c) — valid in
    line-of-sight conditions. Real LoRa links in urban environments have
    additional loss; this model adds ±8 dB of shadow fading jitter.
    """
    if distance_m < 1.0:
        distance_m = 1.0
    fspl_db = 20 * math.log10(distance_m) + _FSPL_CONST
    rssi = tx_power_dbm - fspl_db + random.gauss(0, 4.0)
    return int(max(-140.0, min(-20.0, rssi)))


def _snr_from_rssi(rssi_dbm: int) -> float:
    """
    Derive synthetic SNR from RSSI. LoRa sensitivity floor is ~-137 dBm
    at SF12; noise floor ~-120 dBm at SF7. Linear approximation with jitter.
    """
    noise_floor = -120.0
    snr_raw = rssi_dbm - noise_floor + random.gauss(0, 2.0)
    return round(max(-20.0, min(12.0, snr_raw)), 1)


def _random_node_id() -> str:
    """Generate a Meshtastic-format node ID: !xxxxxxxx (8 hex chars)."""
    val = random.randint(0x10000000, 0xFFFFFFFF)
    return f"!{val:08x}"


def _bearing_offset_m(lat: float, lon: float, bearing_deg: float, dist_m: float):
    """Return (lat2, lon2) after moving dist_m metres on bearing_deg."""
    R = 6371000.0
    d = dist_m / R
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


class MeshtasticPassiveAdapter:
    """
    Generates synthetic Meshtastic passive-listen scenarios as lists of
    ThreatIndicator objects. NODE IS IN CLIENT_MUTE — no transmit path
    exists in this adapter.

    Three scenarios are supported:

    "quiet_mesh"
        0–2 nodes at moderate distances (500–2000 m). Generic civilian
        profiles. Low raw_weight (0.05–0.15). Represents normal background
        mesh activity in a suburban environment.

    "active_spotters"
        3–5 mobile nodes within 300 m of the sentinel node. Node profiles
        drawn from SPOTTER_PROFILES. Low hop counts (0–1) indicating direct
        reception without relaying. High RSSI consistent with proximity.
        raw_weight 0.65–0.90. Represents the M_d(t) signal pattern.

    "dense_civilian"
        20–35 nodes at mixed distances (80–3000 m) with civilian profiles.
        Represents a large community event or festival scenario. High node
        count but low per-node weight (0.05–0.20) since profiles are
        non-threatening. Tests salience engine's ability to distinguish
        density from proximity-with-profile.
    """

    channel     = "MESHTASTIC"
    source_tool = "MeshtasticPassive"

    def generate_scenario(
        self,
        scenario: str,
        node_lat: float,
        node_lon: float,
    ) -> List[ThreatIndicator]:
        if scenario == "quiet_mesh":
            return self._quiet_mesh(node_lat, node_lon)
        elif scenario == "active_spotters":
            return self._active_spotters(node_lat, node_lon)
        elif scenario == "dense_civilian":
            return self._dense_civilian(node_lat, node_lon)
        else:
            raise ValueError(
                f"Unknown scenario '{scenario}'. "
                "Valid scenarios: 'quiet_mesh', 'active_spotters', 'dense_civilian'."
            )

    # ------------------------------------------------------------------
    # Scenario generators
    # ------------------------------------------------------------------

    def _quiet_mesh(self, node_lat: float, node_lon: float) -> List[ThreatIndicator]:
        count = random.randint(0, 2)
        base_time = datetime.now(timezone.utc)
        indicators = []

        for _ in range(count):
            dist_m = random.uniform(500.0, 2000.0)
            bearing = random.uniform(0, 360)
            peer_lat, peer_lon = _bearing_offset_m(node_lat, node_lon, bearing, dist_m)
            rssi = _rssi_from_distance_m(dist_m)
            snr  = _snr_from_rssi(rssi)
            hop  = random.randint(1, 3)
            ts   = base_time + timedelta(seconds=random.uniform(0, 120))
            portnum = random.choice([PORTNUM_NODEINFO, PORTNUM_POSITION, PORTNUM_TELEMETRY])

            indicators.append(self._build_indicator(
                node_id=_random_node_id(),
                peer_lat=peer_lat,
                peer_lon=peer_lon,
                hop_count=hop,
                rssi=rssi,
                snr=snr,
                node_profile=random.choice(CIVILIAN_PROFILES),
                message_type=portnum,
                distance_m=round(dist_m, 1),
                raw_weight=round(random.uniform(0.05, 0.15), 3),
                timestamp=ts,
                tags=["mesh", "civilian", "quiet"],
            ))

        return indicators

    def _active_spotters(self, node_lat: float, node_lon: float) -> List[ThreatIndicator]:
        count = random.randint(3, 5)
        base_time = datetime.now(timezone.utc)
        indicators = []

        for i in range(count):
            # Tight cluster: all within 300 m
            dist_m = random.uniform(30.0, 300.0)
            bearing = random.uniform(0, 360)
            peer_lat, peer_lon = _bearing_offset_m(node_lat, node_lon, bearing, dist_m)
            rssi = _rssi_from_distance_m(dist_m, tx_power_dbm=20.0)
            snr  = _snr_from_rssi(rssi)

            # Direct reception without relay: hop_count 0 or 1
            hop = random.choice([0, 0, 1])

            # Spotter nodes send more NODEINFO and POSITION than TEXT
            portnum = random.choices(
                [PORTNUM_NODEINFO, PORTNUM_POSITION, PORTNUM_TEXT_MESSAGE, PORTNUM_ROUTING],
                weights=[0.40, 0.35, 0.15, 0.10],
            )[0]

            ts = base_time + timedelta(seconds=random.uniform(0, 90))
            profile = random.choice(SPOTTER_PROFILES)

            indicators.append(self._build_indicator(
                node_id=_random_node_id(),
                peer_lat=peer_lat,
                peer_lon=peer_lon,
                hop_count=hop,
                rssi=rssi,
                snr=snr,
                node_profile=profile,
                message_type=portnum,
                distance_m=round(dist_m, 1),
                raw_weight=round(random.uniform(0.65, 0.90), 3),
                timestamp=ts,
                tags=["mesh", "spotter", "proximity", "active"],
            ))

        return indicators

    def _dense_civilian(self, node_lat: float, node_lon: float) -> List[ThreatIndicator]:
        count = random.randint(20, 35)
        base_time = datetime.now(timezone.utc)
        indicators = []

        for _ in range(count):
            dist_m = random.uniform(80.0, 3000.0)
            bearing = random.uniform(0, 360)
            peer_lat, peer_lon = _bearing_offset_m(node_lat, node_lon, bearing, dist_m)
            rssi = _rssi_from_distance_m(dist_m)
            snr  = _snr_from_rssi(rssi)
            hop  = random.choices([0, 1, 2, 3], weights=[0.15, 0.30, 0.35, 0.20])[0]
            portnum = random.choices(
                [PORTNUM_TEXT_MESSAGE, PORTNUM_POSITION, PORTNUM_NODEINFO, PORTNUM_TELEMETRY],
                weights=[0.45, 0.25, 0.20, 0.10],
            )[0]
            ts = base_time + timedelta(seconds=random.uniform(0, 600))

            indicators.append(self._build_indicator(
                node_id=_random_node_id(),
                peer_lat=peer_lat,
                peer_lon=peer_lon,
                hop_count=hop,
                rssi=rssi,
                snr=snr,
                node_profile=random.choice(CIVILIAN_PROFILES),
                message_type=portnum,
                distance_m=round(dist_m, 1),
                raw_weight=round(random.uniform(0.05, 0.20), 3),
                timestamp=ts,
                tags=["mesh", "civilian", "dense"],
            ))

        return indicators

    # ------------------------------------------------------------------
    # Internal builder
    # ------------------------------------------------------------------

    def _build_indicator(
        self,
        node_id: str,
        peer_lat: float,
        peer_lon: float,
        hop_count: int,
        rssi: int,
        snr: float,
        node_profile: str,
        message_type: str,
        distance_m: float,
        raw_weight: float,
        timestamp: datetime,
        tags: List[str],
    ) -> ThreatIndicator:

        is_proximate = distance_m <= 300.0
        is_spotter_profile = node_profile in SPOTTER_PROFILES

        secondary = [f"profile:{node_profile}", f"portnum:{message_type}"]
        if is_proximate:
            secondary.append("proximity:close")
        if hop_count == 0:
            secondary.append("rx:direct")

        return ThreatIndicator(
            event_id=uuid4(),
            timestamp=timestamp,
            channel=self.channel,
            source_tool=self.source_tool,
            latitude=peer_lat,
            longitude=peer_lon,
            primary_id=node_id,
            secondary_ids=secondary,
            metadata={
                "node_id":           node_id,
                "hop_count":         hop_count,
                "rssi":              rssi,
                "snr":               snr,
                "node_profile":      node_profile,
                "message_type":      message_type,
                "distance_m":        distance_m,
                "is_proximate":      is_proximate,
                "is_spotter_profile": is_spotter_profile,
                "client_mute":       True,
                "tx_enabled":        False,
            },
            tags=tags,
            raw_weight=raw_weight,
        )
