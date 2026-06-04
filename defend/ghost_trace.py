"""
ghost_trace.py — GhostTrace deception engine SIMULATION for SENTINEL-NODE.

SENTINEL-NODE synthetic policy demonstration platform.
All data is fictional and used solely to demonstrate system behavior
under simulated enforcement pressure for policymaker education.

IMPORTANT: This module models what an ESP32-C6 running GhostTrace firmware
would generate and outputs synthetic 802.11 frame sequences for analysis of
failure modes and second-order effects.  It does NOT transmit anything.  No
radio hardware is accessed.  No actual 802.11 frames are injected.

The COLLATERAL_PRIVACY_HARM failure mode documented at the bottom of this
module is the most consequential second-order effect: GhostTrace clones OUI
prefixes from real devices observed in the physical environment.  This means
the MAC prefixes of uninvolved bystanders' phones and laptops appear in the
synthetic frame stream, asserting their device identities at locations and
times they were not present.  If a sophisticated WIDS or law-enforcement
capture system retains these frames, innocent bystanders acquire false
evidence trails through no action of their own.  This is a privacy harm
created by the counter-surveillance system itself, not by the surveillance
system it is responding to.
"""

from __future__ import annotations

import math
import random
import secrets
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# OUI constants — realistic vendor prefixes (publicly registered, not secret)
# These are used to model realistic decoy traffic; in GhostTrace operation
# they would be sampled from sniffed real traffic in the vicinity.
# ---------------------------------------------------------------------------

# Apple Inc. registered OUI prefixes (public IEEE registry)
_APPLE_OUIS: List[str] = [
    "F4:F1:5A",  # Apple iPhone / MacBook
    "3C:22:FB",
    "A4:C3:F0",
    "DC:2B:2A",
    "60:F8:1D",
    "8C:85:90",
]

# Samsung Electronics OUI prefixes (public IEEE registry)
_SAMSUNG_OUIS: List[str] = [
    "BC:14:85",  # Samsung Galaxy
    "F4:42:8F",
    "8C:C8:4B",
    "2C:F8:9F",
    "44:65:0D",
]

# Google / Pixel OUI prefixes (public IEEE registry)
_PIXEL_OUIS: List[str] = [
    "F4:60:E2",  # Google Pixel
    "4C:BC:98",
    "80:B4:A2",
    "D4:F5:47",
    "48:B0:2D",
]

_ALL_VENDOR_OUIS: List[str] = _APPLE_OUIS + _SAMSUNG_OUIS + _PIXEL_OUIS


# ---------------------------------------------------------------------------
# Realistic information-element fingerprints by vendor class
# IEs are 802.11 probe-request optional fields that fingerprint the device OS.
# These are simplified synthetic representations.
# ---------------------------------------------------------------------------

_IE_PROFILES: Dict[str, dict] = {
    "apple": {
        "supported_rates": [1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54],
        "ht_capabilities": True,
        "vht_capabilities": True,
        "he_capabilities": True,
        "vendor_specific": "APPLE_AWDL",
        "power_capability_dbm": 20,
        "rm_capabilities": True,
    },
    "samsung": {
        "supported_rates": [1, 2, 5.5, 11, 6, 12, 24],
        "ht_capabilities": True,
        "vht_capabilities": True,
        "he_capabilities": True,
        "vendor_specific": "SAMSUNG_SISOAP",
        "power_capability_dbm": 20,
        "rm_capabilities": False,
    },
    "pixel": {
        "supported_rates": [1, 2, 5.5, 11, 6, 9, 12, 18, 24, 36, 48, 54],
        "ht_capabilities": True,
        "vht_capabilities": True,
        "he_capabilities": True,
        "vendor_specific": "GOOGLE_FIRA",
        "power_capability_dbm": 18,
        "rm_capabilities": True,
    },
}


def _vendor_class_for_oui(oui: str) -> str:
    if oui in _APPLE_OUIS:
        return "apple"
    if oui in _SAMSUNG_OUIS:
        return "samsung"
    return "pixel"


def _random_mac_from_oui(oui: str) -> str:
    """Generate a locally-administered unicast MAC from a vendor OUI prefix."""
    suffix = ":".join(f"{secrets.randbelow(256):02X}" for _ in range(3))
    return f"{oui}:{suffix}"


# ---------------------------------------------------------------------------
# Virtual device FSM
# ---------------------------------------------------------------------------

@dataclass
class _VirtualDevice:
    """State machine representing a single synthetic 802.11 device."""
    mac: str
    oui: str
    vendor_class: str
    sequence_number: int = field(default_factory=lambda: random.randint(0, 4095))
    # Poisson rate in Hz; each device gets a slightly different rate
    tx_rate_hz: float = field(default_factory=lambda: random.uniform(0.05, 0.15))

    def next_sequence(self) -> int:
        """Advance sequence counter by 1–16 (fragmentation/retry simulation)."""
        increment = random.randint(1, 16)
        self.sequence_number = (self.sequence_number + increment) % 4096
        return self.sequence_number

    def ie_profile(self, cached_overrides: Optional[dict] = None) -> dict:
        base = dict(_IE_PROFILES[self.vendor_class])
        if cached_overrides:
            base.update(cached_overrides)
        return base


# ---------------------------------------------------------------------------
# GhostTraceSimulator
# ---------------------------------------------------------------------------

class GhostTraceSimulator:
    """Models the GhostTrace 802.11 deception layer for policy failure-mode analysis.

    GhostTrace is a counter-surveillance technique where an embedded device
    (ESP32-C6 in the reference implementation) injects synthetic 802.11
    probe-request and beacon frames to inflate the apparent number of devices
    present in an area, disrupting WIDS-based crowd tracking and checkpoint
    correlation.

    This class simulates the frame generator and provides analytical outputs:
    - Synthetic frame sequences for adversarial analysis
    - Correlation disruption metrics (bipartite covariance formula)
    - Structured failure-mode catalogue

    All outputs are synthetic.  No 802.11 frames are transmitted.

    Parameters
    ----------
    target_device_count:
        Number of virtual devices the simulator maintains.  Each device has
        its own stateful sequence-number FSM and Poisson emission rate.
    tx_rate_mean:
        Mean transmission rate in Hz across all virtual devices.
        Default 0.083 Hz ≈ 5 frames/minute per device.
    """

    def __init__(
        self,
        target_device_count: int = 12,
        tx_rate_mean: float = 0.083,
    ) -> None:
        self.target_device_count = target_device_count
        self.tx_rate_mean = tx_rate_mean

        # Sniffed environment: OUI prefixes and IE snapshots from real devices
        self._sniffed_ouis: List[str] = []
        self._sniffed_ie_cache: Dict[str, dict] = {}  # oui → ie overrides

        # Virtual device pool (FSM per device)
        self._virtual_devices: List[_VirtualDevice] = []
        self._initialise_device_pool()

        logger.info(
            "GhostTraceSimulator init target_device_count=%d tx_rate_mean=%.4f Hz",
            target_device_count,
            tx_rate_mean,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _initialise_device_pool(self) -> None:
        """Populate the virtual device pool from the best available OUI source."""
        source_ouis = self._sniffed_ouis if self._sniffed_ouis else _ALL_VENDOR_OUIS
        self._virtual_devices = []
        for _ in range(self.target_device_count):
            oui = random.choice(source_ouis)
            vendor_class = _vendor_class_for_oui(oui)
            mac = _random_mac_from_oui(oui)
            dev = _VirtualDevice(
                mac=mac,
                oui=oui,
                vendor_class=vendor_class,
                tx_rate_hz=max(0.05, random.gauss(self.tx_rate_mean, self.tx_rate_mean * 0.3)),
            )
            self._virtual_devices.append(dev)

    def _poisson_inter_arrival(self, rate_hz: float) -> float:
        """Sample an inter-arrival time from an exponential distribution (Poisson process)."""
        # Clamp rate to avoid division-by-zero or unrealistic values
        rate_hz = max(1e-4, rate_hz)
        return random.expovariate(rate_hz)

    def _rssi_for_device(self) -> int:
        """Return a plausible RSSI in dBm for a device 2–30 m away (free-space model)."""
        # Simplified log-distance path loss: RSSI = -40 - 20*log10(d)
        distance_m = random.uniform(2.0, 30.0)
        rssi = -40 - 20 * math.log10(distance_m)
        # Add ±5 dBm shadow-fading jitter
        rssi += random.gauss(0, 5)
        return int(round(rssi))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sniff_environment(self, real_devices: List[dict]) -> None:
        """Record OUI prefixes and IE fingerprints from observed real devices.

        In deployment, the ESP32-C6 passively monitors the 2.4 GHz and 5 GHz
        channels in monitor mode before activating the decoy transmitter.  The
        sniffed fingerprints make the synthetic frames plausible.

        NOTE — COLLATERAL PRIVACY HARM: The OUI and IE data recorded here
        belongs to real people's devices.  When GhostTrace later uses these
        fingerprints to generate decoy frames, it is asserting the device
        identities of uninvolved bystanders at times and locations they may
        not have been present.  See failure_modes() for a full treatment of
        this second-order effect.

        Parameters
        ----------
        real_devices:
            List of dicts, each with at minimum ``"oui"`` (str) and
            optionally ``"information_elements"`` (dict).  Simulates the
            passive-sniff output the firmware would produce.
        """
        self._sniffed_ouis = []
        self._sniffed_ie_cache = {}

        for device in real_devices:
            oui = device.get("oui")
            if oui:
                self._sniffed_ouis.append(oui)
                if "information_elements" in device:
                    self._sniffed_ie_cache[oui] = device["information_elements"]

        # Re-initialise device pool from sniffed OUI distribution
        self._initialise_device_pool()

        logger.info(
            "sniff_environment recorded oui_count=%d ie_cache_entries=%d",
            len(self._sniffed_ouis),
            len(self._sniffed_ie_cache),
        )

    def generate_decoy_burst(self, duration_seconds: int = 30) -> List[dict]:
        """Generate a synthetic burst of 802.11 frames spanning duration_seconds.

        Each virtual device emits frames following its own Poisson process.
        Sequence numbers advance via the per-device FSM.  Frame types alternate
        between probe_req and beacon with a 70/30 split (probe-heavy, matching
        real device behaviour when scanning for known networks).

        Parameters
        ----------
        duration_seconds:
            Wall-clock window to simulate.

        Returns
        -------
        List[dict]
            Synthetic frame records sorted by timestamp.  Each dict contains:
            mac, oui, sequence_number, timestamp (ISO-8601 str),
            rssi_dbm, information_elements (dict), frame_type (str).
        """
        frames: List[dict] = []
        base_ts = datetime.now(timezone.utc).timestamp()

        for device in self._virtual_devices:
            t = 0.0
            while t < duration_seconds:
                inter_arrival = self._poisson_inter_arrival(device.tx_rate_hz)
                t += inter_arrival
                if t >= duration_seconds:
                    break

                seq = device.next_sequence()
                ie_overrides = self._sniffed_ie_cache.get(device.oui)
                ie_profile = device.ie_profile(ie_overrides)
                frame_type = "probe_req" if random.random() < 0.70 else "beacon"
                abs_ts = datetime.fromtimestamp(base_ts + t, tz=timezone.utc)

                frames.append({
                    "mac": device.mac,
                    "oui": device.oui,
                    "sequence_number": seq,
                    "timestamp": abs_ts.isoformat(),
                    "rssi_dbm": self._rssi_for_device(),
                    "information_elements": ie_profile,
                    "frame_type": frame_type,
                })

        frames.sort(key=lambda f: f["timestamp"])
        logger.debug(
            "generate_decoy_burst duration=%ds frames_generated=%d",
            duration_seconds,
            len(frames),
        )
        return frames

    def compute_correlation_disruption(
        self,
        real_device_count: int,
        checkpoint_count: int,
    ) -> dict:
        """Quantify how much GhostTrace degrades checkpoint correlation confidence.

        Uses the bipartite covariance formula from the academic literature on
        crowd anonymity:

            C(d, v) = cov(D_d, D_v) / sqrt(var(D_d) * var(D_v))

        where D_d is the detection event vector for real device d across
        checkpoint_count checkpoints, and D_v is the corresponding vector for
        a virtual (decoy) device v.

        Baseline: without injection, real devices have high pairwise correlation
        because surveillance checkpoints can reliably correlate the same device
        across locations (same MAC, same IE fingerprint).

        Post-injection: the inflated anonymity set (real + virtual devices)
        forces any checkpoint-to-checkpoint correlation algorithm to distribute
        its confidence across more candidates, degrading per-device confidence.

        This is a first-principles model, not a fit to empirical data.

        Parameters
        ----------
        real_device_count:
            Number of real devices present (ground truth the simulator knows
            but the surveillance system does not).
        checkpoint_count:
            Number of surveillance checkpoints or observation windows.

        Returns
        -------
        dict
            baseline_confidence, post_injection_confidence,
            anonymity_set_size, disruption_ratio.
        """
        if checkpoint_count < 2:
            checkpoint_count = 2

        virtual_count = self.target_device_count
        anonymity_set_size = real_device_count + virtual_count

        # Baseline: surveillance has near-perfect correlation when there are no
        # decoys.  Model baseline confidence as inversely proportional to the
        # natural variability at real_device_count.
        # C_baseline = 1 - 1/(real_device_count + 1)  (approaches 1 as crowd grows,
        # because fixed devices are easy to track)
        baseline_confidence = max(0.0, min(1.0, 1.0 - 1.0 / (real_device_count + 1)))

        # Post-injection: the effective anonymity set inflates to anonymity_set_size.
        # The algorithm must now pick 1 real device out of anonymity_set_size candidates.
        # Correlation confidence degrades as:
        #   C_post = C_base * (real_device_count / anonymity_set_size)^0.5
        # The square-root exponent reflects that bipartite matching partial information
        # still narrows the field faster than random chance.
        ratio = real_device_count / anonymity_set_size if anonymity_set_size > 0 else 1.0
        post_injection_confidence = baseline_confidence * math.sqrt(ratio)

        # Disruption ratio: how much confidence degraded (1.0 = completely disrupted)
        if baseline_confidence > 0:
            disruption_ratio = 1.0 - (post_injection_confidence / baseline_confidence)
        else:
            disruption_ratio = 0.0

        result = {
            "baseline_confidence": round(baseline_confidence, 4),
            "post_injection_confidence": round(post_injection_confidence, 4),
            "anonymity_set_size": anonymity_set_size,
            "disruption_ratio": round(disruption_ratio, 4),
        }
        logger.debug("compute_correlation_disruption %s", result)
        return result

    def failure_modes(self) -> List[dict]:
        """Return a structured catalogue of GhostTrace failure modes.

        Each entry describes a condition under which the deception fails —
        either by being detected by a sufficiently sophisticated adversary,
        or by causing unintended harm to third parties.

        The COLLATERAL_PRIVACY_HARM entry is intentionally the most detailed:
        it represents a second-order effect where the counter-surveillance
        system becomes itself a source of privacy violations for uninvolved
        bystanders whose device identities are cloned into the synthetic frame
        stream.

        Returns
        -------
        List[dict]
            Ordered list of failure-mode dicts, each with:
            id (str), name (str), severity (str), detection_vector (str),
            description (str), second_order_harm (bool), mitigation (str).
        """
        return [
            {
                "id": "WIDS_SEQUENCE_DETECTION",
                "name": "WIDS Per-MAC Sequence Continuity Tracking",
                "severity": "HIGH",
                "detection_vector": "Wireless Intrusion Detection System",
                "description": (
                    "A WIDS that tracks per-MAC sequence number continuity across "
                    "channels will observe GhostTrace's FSM state.  Any sequence "
                    "number reset — caused by device pool re-initialisation, "
                    "firmware crash, or watchdog reboot — creates a discontinuity "
                    "that real devices do not exhibit.  A reset from e.g. 3200 back "
                    "to a value below 100 on a device that was recently active is a "
                    "strong anomaly signal.  The FSM must maintain perfect continuity "
                    "across all channels simultaneously; a single reset event is "
                    "sufficient for the WIDS to flag all frames from that MAC as "
                    "synthetic and begin filtering the virtual device from correlation."
                ),
                "second_order_harm": False,
                "mitigation": (
                    "Persist FSM state to non-volatile storage with crash-safe "
                    "write-ahead log.  Randomise initial sequence number per boot "
                    "to avoid the 'starts near zero' pattern.  Accept that perfect "
                    "continuity across hardware resets is an unsolved constraint."
                ),
            },
            {
                "id": "RSSI_ANOMALY",
                "name": "RSSI / Spatial Mismatch Detection",
                "severity": "HIGH",
                "detection_vector": "Multi-antenna RSSI geolocation",
                "description": (
                    "Checkpoints equipped with multi-antenna arrays estimate device "
                    "position from RSSI or TDOA.  GhostTrace decoys are generated "
                    "at a fixed transmit power; their RSSI at the receiver reflects "
                    "the true distance from the GhostTrace hardware, not the claimed "
                    "or implied device location.  If a WIDS cross-correlates RSSI "
                    "across two or more spatially separated antennas, all decoy "
                    "frames will geolocate to the same physical source — the "
                    "GhostTrace hardware — rather than being distributed across the "
                    "crowd.  A cluster of 12 'different' devices all geolocating to "
                    "a single point is a strong synthetic-traffic indicator."
                ),
                "second_order_harm": False,
                "mitigation": (
                    "Vary per-frame TX power at the firmware level.  Deploy multiple "
                    "GhostTrace nodes spatially distributed so RSSI clustering maps "
                    "to different source locations.  Neither approach fully defeats "
                    "a TDOA-capable adversary with dense antenna coverage."
                ),
            },
            {
                "id": "IE_STALENESS",
                "name": "Information Element Staleness",
                "severity": "MEDIUM",
                "detection_vector": "WIDS IE consistency tracking",
                "description": (
                    "GhostTrace caches the information-element (IE) profiles sniffed "
                    "from real devices during the initialisation phase.  If those real "
                    "devices subsequently leave the area, the IE fingerprints they "
                    "contributed to the cache no longer match any device observable "
                    "in the environment.  A WIDS tracking IE consistency over time "
                    "will observe frames claiming a vendor-specific IE that no real "
                    "device in the current scan window supports.  Stale IEs create "
                    "an outlier-flagging opportunity that worsens as the observation "
                    "window lengthens — by the end of a long deployment, the sniff "
                    "cache may be entirely stale."
                ),
                "second_order_harm": False,
                "mitigation": (
                    "Re-sniff the environment periodically and prune the IE cache "
                    "as devices depart.  In practice the ESP32-C6 cannot run passive "
                    "monitor mode and active injection simultaneously on the same "
                    "radio — a hardware-level constraint that makes continuous "
                    "re-sniffing difficult without a second radio interface."
                ),
            },
            {
                "id": "SURVEILLANCE_ML_ADAPTATION",
                "name": "ML-Based Poisson Signature Detection",
                "severity": "HIGH",
                "detection_vector": "Supervised anomaly detection on frame inter-arrival times",
                "description": (
                    "GhostTrace generates frames following a Poisson process.  Real "
                    "device frame inter-arrival times are not Poisson — they are "
                    "governed by user behaviour (bursty when unlocking a phone, "
                    "quiescent when the phone is idle and screen-off), OS scan "
                    "scheduler jitter, and backoff algorithms.  A sufficiently "
                    "sophisticated ML-based WIDS trained on real device inter-arrival "
                    "distributions can identify GhostTrace's Poisson signature as an "
                    "anomaly class distinct from real device traffic.  As GhostTrace "
                    "is deployed more widely, surveillance vendors gain more labeled "
                    "training data and the classifier improves.  This is an arms-race "
                    "dynamic: GhostTrace would need to model realistic bursty user "
                    "behaviour — a substantially harder problem — to evade this class "
                    "of detector."
                ),
                "second_order_harm": False,
                "mitigation": (
                    "Replace the Poisson process with a Hidden Markov Model (HMM) "
                    "that incorporates screen-on/off state transitions and OS scan "
                    "scheduler behaviour.  This substantially increases implementation "
                    "complexity and does not guarantee evasion against a well-trained "
                    "adversary with dense training data."
                ),
            },
            {
                "id": "COLLATERAL_PRIVACY_HARM",
                "name": "Bystander OUI Cloning — Collateral Privacy Harm",
                "severity": "CRITICAL",
                "detection_vector": "N/A — this is a harm caused by GhostTrace, not a detection vector",
                "description": (
                    "SECOND-ORDER EFFECT — HARM CAUSED BY THE COUNTER-SURVEILLANCE "
                    "SYSTEM ITSELF, NOT BY THE SURVEILLANCE SYSTEM IT OPPOSES:\n\n"
                    "GhostTrace populates its OUI pool by passively sniffing real "
                    "802.11 probe requests from devices in the vicinity during the "
                    "initialisation phase.  These are real people's phones, laptops, "
                    "and tablets.  The OUI prefixes (and potentially IE fingerprints) "
                    "captured belong to uninvolved bystanders who have not consented "
                    "to their device identities being used in a counter-surveillance "
                    "operation.\n\n"
                    "When GhostTrace later generates decoy frames using these OUI "
                    "prefixes, it asserts the presence of those device classes at "
                    "specific times and locations.  If a surveillance system — or a "
                    "digital forensics system used in later legal proceedings — "
                    "captures and retains these frames, the captured data creates a "
                    "false evidence chain linking bystanders' device fingerprints to "
                    "a location and event they may not have participated in.\n\n"
                    "This is structurally similar to a framing attack: an innocent "
                    "person's device identity is used, without their knowledge, to "
                    "generate plausible-looking presence data at a place and time the "
                    "person did not choose to create.  The counter-surveillance system "
                    "designed to protect protesters may expose uninvolved bystanders — "
                    "passersby, residents, nearby business workers — to scrutiny they "
                    "did not invite and cannot detect or opt out of.\n\n"
                    "This failure mode cannot be fully mitigated by the GhostTrace "
                    "design as specified.  It is an inherent consequence of using real "
                    "local device fingerprints as the source of decoy authenticity.  "
                    "Switching to entirely synthetic OUIs (not from local devices) "
                    "reduces the collateral harm but also makes the decoys less "
                    "realistic and easier to detect."
                ),
                "second_order_harm": True,
                "mitigation": (
                    "Use only synthetic OUIs from a pre-generated pool unrelated to "
                    "devices physically present.  Accept the trade-off that synthetic "
                    "OUIs are more detectable by a well-tuned WIDS.  Alternatively, "
                    "limit OUI sniffing to devices whose operators have explicitly "
                    "opted in — but this requires a coordination mechanism that "
                    "itself creates a detectable pattern and requires awareness of "
                    "GhostTrace operation from bystanders who may not want to be "
                    "aware of it."
                ),
            },
        ]
