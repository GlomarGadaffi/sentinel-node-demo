"""
Synthetic EDACS/P25 trunked radio control channel adapter.

All data produced by this module is SYNTHETIC. No real radio hardware,
no actual RF capture, no live trunking system is involved. This adapter
generates representative trunking traffic patterns for policy demonstration
purposes only.

EDACS (Enhanced Digital Access Communication System) encodes control channel
messages as 21-bit words transmitted at 9600 baud on a designated control
channel LCN. Each word carries a logical channel ID (LCID) type field,
a group/unit address, and ancillary routing bits. This adapter models the
two frame types most relevant to mobilization detection: Group Grant (0x01)
and Group Affiliation (0x06), following the EDACS SCAT specification.

The "tactical_surge" scenario models the T-15 mobilization signal described
in the accompanying policy paper: a statistically anomalous density of
grant and affiliation frames on tactical subfleet prefixes (200xx–209xx)
within a 90-second window, cross-correlated with aviation and mesh signal
inputs to produce a composite salience score.
"""

import random
import math
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4

from adapters.base import ThreatIndicator


# ---------------------------------------------------------------------------
# EDACS 21-bit word structure constants
# ---------------------------------------------------------------------------
# Bit layout per EDACS SCAT spec (MSB-first):
#   [20:18]  LCID type   (3 bits)  — frame type discriminator
#   [17:11]  LCID        (7 bits)  — logical channel number
#   [10:0]   GROUP/UNIT  (11 bits) — talkgroup or unit address
#
# Selected LCID type codes:
LCID_TYPE_GROUP_GRANT       = 0x01   # Voice channel grant to a talkgroup
LCID_TYPE_INDIVIDUAL_GRANT  = 0x02   # Voice channel grant to a unit
LCID_TYPE_QUEUE             = 0x04   # Channel queue notification
LCID_TYPE_AFFILIATION       = 0x06   # Unit-to-talkgroup affiliation
LCID_TYPE_DEAFFILIATION     = 0x07   # Unit deaffiliation
LCID_TYPE_EMERGENCY         = 0x05   # Emergency activation
LCID_TYPE_STATUS            = 0x03   # Status/telemetry frame

# Subfleet prefix bands (upper two decimal digits of talkgroup ID)
TACTICAL_SUBFLEET_PREFIXES = (200, 201, 202, 203, 204, 205, 206, 207, 208, 209)
MUNICIPAL_SUBFLEET_PREFIXES = (100, 101, 102, 103, 110, 111, 120, 130, 150, 151)

# Realistic municipal talkgroup IDs (decimal) for a mid-sized metro system
MUNICIPAL_TALKGROUPS = [
    10016,   # Fire Dispatch Alpha
    10017,   # Fire Dispatch Bravo
    10024,   # EMS Operations
    10025,   # EMS Supervisor
    11000,   # PD Patrol Zone 1
    11001,   # PD Patrol Zone 2
    11002,   # PD Patrol Zone 3
    11010,   # PD Investigations
    11020,   # PD Traffic
    12000,   # Public Works
    12010,   # Transit Authority
    15000,   # Emergency Management
]

# Tactical talkgroup IDs — subfleet 200xx–209xx used by regional tactical teams
TACTICAL_TALKGROUPS = [
    20001,   # Tac-1 Command
    20002,   # Tac-1 Perimeter
    20003,   # Tac-1 Assault
    20100,   # Tac-2 Command
    20101,   # Tac-2 Entry
    20200,   # Tac-3 (Regional)
    20300,   # Air-Ground Coordination
    20400,   # EOD Coordination
    20500,   # Intel / Surveillance Coordination
    20501,   # SIGINT Support
    20600,   # Interagency Fusion
    20700,   # Crisis Negotiation
    20800,   # Rapid Deployment
    20900,   # Medical-Tactical
    20901,   # CRIT (Critical Response)
    20910,   # Forward Element
]


def parse_lcid_frame(raw_word: int) -> dict:
    """
    Decode a single 21-bit EDACS control channel word.

    The caller is responsible for assembling the raw 21-bit value from
    whatever framing layer delivered it (e.g., after FSK demodulation and
    RS(16,8) error correction). This function performs pure bit extraction
    with no I/O or state.

    Bit layout (MSB = bit 20):
        [20:18]  lcid_type  — frame type discriminator (3 bits)
        [17:11]  lcid       — logical channel number 0–127 (7 bits)
        [10:0]   group      — talkgroup or unit address 0–2047 (11 bits)

    Note: Real EDACS systems often encode the full talkgroup in a fleet/
    subfleet/group triplet rather than a flat 11-bit field. This stub uses
    the flat representation for clarity.

    Returns a dict with integer fields plus a human-readable type_name.
    """
    if not (0 <= raw_word <= 0x1FFFFF):
        raise ValueError(f"raw_word 0x{raw_word:06X} exceeds 21-bit range")

    lcid_type = (raw_word >> 18) & 0x07
    lcid      = (raw_word >> 11) & 0x7F
    group     = raw_word & 0x07FF

    type_names = {
        LCID_TYPE_GROUP_GRANT:      "GROUP_GRANT",
        LCID_TYPE_INDIVIDUAL_GRANT: "INDIVIDUAL_GRANT",
        LCID_TYPE_STATUS:           "STATUS",
        LCID_TYPE_QUEUE:            "QUEUE",
        LCID_TYPE_EMERGENCY:        "EMERGENCY",
        LCID_TYPE_AFFILIATION:      "AFFILIATION",
        LCID_TYPE_DEAFFILIATION:    "DEAFFILIATION",
    }

    return {
        "raw_word":    raw_word,
        "lcid_type":   lcid_type,
        "type_name":   type_names.get(lcid_type, f"UNKNOWN_0x{lcid_type:02X}"),
        "lcid":        lcid,
        "group":       group,
    }


class EDACSSyntheticAdapter:
    """
    Generates synthetic EDACS/P25 trunking control channel scenarios as
    lists of ThreatIndicator objects for consumption by the SENTINEL-NODE
    salience engine.

    Three scenarios are supported:

    "routine_patrol"
        Sparse municipal dispatch traffic reflecting normal daytime activity.
        Grant density is low (3–7 events per window). Talkgroup IDs are drawn
        from municipal subfleet ranges. raw_weight 0.1–0.2.

    "quiet_period"
        Near-zero traffic representing overnight or holiday lulls. 0–2 events,
        all municipal. raw_weight 0.05–0.1.

    "tactical_surge"
        Dense burst of Group Grant and Affiliation frames on tactical subfleet
        prefixes (200xx–209xx). 18–32 events per 90-second synthetic window,
        weighted 0.9. Models the T-15 signal: a mobilization precursor
        characterized by rapid affiliation churn on tactical talkgroups before
        overt on-scene activity begins. The rolling_baseline_rate and
        current_rate metadata fields expose the anomaly ratio to the salience
        engine's trunking term W_a * T_d(t).
    """

    channel   = "EDACS"
    source_tool = "EDACSSynthetic"

    # Baseline grant rate for a quiet municipal system: grants per 90-second window
    _BASELINE_RATE_ROUTINE  = 5.2    # historical mean, municipal channels
    _BASELINE_RATE_TACTICAL = 1.1    # tactical channels when not active

    def generate_scenario(self, scenario: str) -> List[ThreatIndicator]:
        if scenario == "routine_patrol":
            return self._routine_patrol()
        elif scenario == "tactical_surge":
            return self._tactical_surge()
        elif scenario == "quiet_period":
            return self._quiet_period()
        else:
            raise ValueError(
                f"Unknown scenario '{scenario}'. "
                "Valid scenarios: 'routine_patrol', 'tactical_surge', 'quiet_period'."
            )

    # ------------------------------------------------------------------
    # Scenario generators
    # ------------------------------------------------------------------

    def _routine_patrol(self) -> List[ThreatIndicator]:
        count = random.randint(3, 7)
        indicators = []
        base_time = datetime.now(timezone.utc)

        for i in range(count):
            tg_id = random.choice(MUNICIPAL_TALKGROUPS)
            lcid_type = random.choice([LCID_TYPE_GROUP_GRANT, LCID_TYPE_STATUS])
            lcid = random.randint(1, 30)
            grant_count = random.randint(1, 3)
            prefix = tg_id // 100

            ts = base_time + timedelta(seconds=random.uniform(0, 85))
            indicators.append(self._build_indicator(
                talkgroup_id=tg_id,
                lcid_type=lcid_type,
                lcid=lcid,
                subfleet_prefix=prefix,
                grant_count=grant_count,
                affiliation_count=random.randint(0, 1),
                rolling_baseline_rate=self._BASELINE_RATE_ROUTINE,
                current_rate=count / 90.0,
                raw_weight=round(random.uniform(0.1, 0.2), 3),
                timestamp=ts,
                tags=["municipal", "patrol"],
            ))

        return indicators

    def _quiet_period(self) -> List[ThreatIndicator]:
        count = random.randint(0, 2)
        indicators = []
        base_time = datetime.now(timezone.utc)

        for i in range(count):
            tg_id = random.choice(MUNICIPAL_TALKGROUPS)
            ts = base_time + timedelta(seconds=random.uniform(0, 85))
            indicators.append(self._build_indicator(
                talkgroup_id=tg_id,
                lcid_type=LCID_TYPE_STATUS,
                lcid=random.randint(1, 20),
                subfleet_prefix=tg_id // 100,
                grant_count=1,
                affiliation_count=0,
                rolling_baseline_rate=self._BASELINE_RATE_ROUTINE,
                current_rate=count / 90.0,
                raw_weight=round(random.uniform(0.05, 0.10), 3),
                timestamp=ts,
                tags=["municipal", "quiet"],
            ))

        return indicators

    def _tactical_surge(self) -> List[ThreatIndicator]:
        count = random.randint(18, 32)
        indicators = []
        base_time = datetime.now(timezone.utc)

        # Tactical surge: 90% tactical talkgroups, 10% bleed-through on municipal
        for i in range(count):
            is_tactical = random.random() < 0.9

            if is_tactical:
                tg_id = random.choice(TACTICAL_TALKGROUPS)
                lcid_type = random.choices(
                    [LCID_TYPE_GROUP_GRANT, LCID_TYPE_AFFILIATION,
                     LCID_TYPE_EMERGENCY, LCID_TYPE_QUEUE],
                    weights=[0.50, 0.35, 0.08, 0.07],
                )[0]
                lcid = random.randint(20, 60)  # mid-range LCNs reserved for tactical
                weight = round(random.uniform(0.80, 0.95), 3)
                tags = ["tactical", "surge", "t15_signal"]
            else:
                tg_id = random.choice(MUNICIPAL_TALKGROUPS)
                lcid_type = random.choice([LCID_TYPE_GROUP_GRANT, LCID_TYPE_AFFILIATION])
                lcid = random.randint(1, 30)
                weight = round(random.uniform(0.15, 0.25), 3)
                tags = ["municipal", "bleedthrough"]

            # Burst timing: grants cluster in the first 40 seconds of the window
            t_offset = random.betavariate(2.0, 4.0) * 90.0
            ts = base_time + timedelta(seconds=t_offset)

            grant_count = random.randint(1, 5) if is_tactical else 1
            aff_count   = random.randint(1, 4) if lcid_type == LCID_TYPE_AFFILIATION else 0

            indicators.append(self._build_indicator(
                talkgroup_id=tg_id,
                lcid_type=lcid_type,
                lcid=lcid,
                subfleet_prefix=tg_id // 100,
                grant_count=grant_count,
                affiliation_count=aff_count,
                rolling_baseline_rate=self._BASELINE_RATE_TACTICAL,
                current_rate=count / 90.0,
                raw_weight=weight,
                timestamp=ts,
                tags=tags,
            ))

        return indicators

    # ------------------------------------------------------------------
    # Internal builder
    # ------------------------------------------------------------------

    def _build_indicator(
        self,
        talkgroup_id: int,
        lcid_type: int,
        lcid: int,
        subfleet_prefix: int,
        grant_count: int,
        affiliation_count: int,
        rolling_baseline_rate: float,
        current_rate: float,
        raw_weight: float,
        timestamp: datetime,
        tags: List[str],
    ) -> ThreatIndicator:

        type_names = {
            LCID_TYPE_GROUP_GRANT:      "GROUP_GRANT",
            LCID_TYPE_INDIVIDUAL_GRANT: "INDIVIDUAL_GRANT",
            LCID_TYPE_STATUS:           "STATUS",
            LCID_TYPE_QUEUE:            "QUEUE",
            LCID_TYPE_EMERGENCY:        "EMERGENCY",
            LCID_TYPE_AFFILIATION:      "AFFILIATION",
            LCID_TYPE_DEAFFILIATION:    "DEAFFILIATION",
        }

        # Surge ratio: how far current_rate exceeds the rolling baseline
        if rolling_baseline_rate > 0:
            surge_ratio = round(current_rate / rolling_baseline_rate, 4)
        else:
            surge_ratio = 0.0

        return ThreatIndicator(
            event_id=uuid4(),
            timestamp=timestamp,
            channel=self.channel,
            source_tool=self.source_tool,
            latitude=None,
            longitude=None,
            primary_id=str(talkgroup_id),
            secondary_ids=[f"lcid:{lcid}", f"prefix:{subfleet_prefix}"],
            metadata={
                "lcid_type":             lcid_type,
                "lcid_type_name":        type_names.get(lcid_type, "UNKNOWN"),
                "lcid":                  lcid,
                "talkgroup_id":          talkgroup_id,
                "subfleet_prefix":       subfleet_prefix,
                "grant_count":           grant_count,
                "affiliation_count":     affiliation_count,
                "rolling_baseline_rate": rolling_baseline_rate,
                "current_rate":          round(current_rate, 4),
                "surge_ratio":           surge_ratio,
                "is_tactical_subfleet":  subfleet_prefix in TACTICAL_SUBFLEET_PREFIXES,
            },
            tags=tags,
            raw_weight=raw_weight,
        )
