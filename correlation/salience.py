"""
salience.py — Real-time composite salience score engine.

Implements S(t) from the SENTINEL-NODE paper:

    S(t) = W_a * T_d(t) + A_p(t) + M_d(t)

Where:
    T_d(t) = (current_rate - baseline_ema) / baseline_std
             [trunking density, z-score normalised]

    A_p(t) = Σ_i  W_a_i / distance_km_i
             [aviation proximity, inverse-distance weighted]

    M_d(t) = Σ_j  node_weight_j / distance_m_j * 1000
             [mesh density, inverse-distance weighted]

    W_a    = agency weight from agency_db

SENTINEL-NODE is a synthetic policy demonstration platform.
All data is fictional; no real RF or hardware is involved.

Failure modes
-------------
Three named failure modes are implemented and flagged on every transition:

    FALSE_POSITIVE_DENSE_CIVILIAN
        A large public gathering (concert, protest) floods the mesh layer
        with civilian nodes, pushing M_d high enough to trigger DEFENDING
        when no real enforcement operation is present.  Detectable when
        every mesh node's metadata["profile"] is "civilian" and none carry
        the "tactical" tag.

    FALSE_POSITIVE_AVIATION_COMMERCIAL
        A commercial departure from a nearby airport passes close to the
        node at low altitude, momentarily spiking A_p.  Detectable when
        the aviation indicator's metadata["altitude_ft"] > 5000 and
        metadata.get("orbit_pattern") is False.

    FALSE_NEGATIVE_SUPPRESSED_MESH
        An adversary jams or selectively blocks meshtastic propagation,
        driving M_d to zero during an actual operation.  The engine may
        under-score the threat.  Detectable when previous M_d was
        non-zero but current M_d == 0 while other terms remain elevated.
"""

import math
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from uuid import uuid4

from adapters.base import ModeTransition, SalienceSnapshot, ThreatIndicator
from correlation.agency_db import get_agency_weight, is_surveillance_icao


# ---------------------------------------------------------------------------
# Failure-mode flag constants
# ---------------------------------------------------------------------------

FALSE_POSITIVE_DENSE_CIVILIAN = "FALSE_POSITIVE_DENSE_CIVILIAN"
"""High mesh density from a public event triggering DEFENDING incorrectly."""

FALSE_POSITIVE_AVIATION_COMMERCIAL = "FALSE_POSITIVE_AVIATION_COMMERCIAL"
"""Commercial flight at low altitude near node spiking A_p."""

FALSE_NEGATIVE_SUPPRESSED_MESH = "FALSE_NEGATIVE_SUPPRESSED_MESH"
"""Adversarial mesh suppression driving M_d to zero during a real operation."""


# ---------------------------------------------------------------------------
# Internal geometry helpers
# ---------------------------------------------------------------------------

_EARTH_RADIUS_KM = 6371.0


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres between two WGS-84 points."""
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return 2 * _EARTH_RADIUS_KM * math.asin(math.sqrt(a))


def _safe_distance_km(
    lat1: Optional[float],
    lon1: Optional[float],
    lat2: Optional[float],
    lon2: Optional[float],
    floor_km: float = 0.05,
) -> float:
    """Return haversine distance, clamped to floor_km to avoid division by zero."""
    if any(v is None for v in (lat1, lon1, lat2, lon2)):
        return 1.0  # assume 1 km when location is unknown
    return max(_haversine_km(lat1, lon1, lat2, lon2), floor_km)


# ---------------------------------------------------------------------------
# EMA / variance tracker
# ---------------------------------------------------------------------------

class _RunningStats:
    """Exponential moving average and variance tracker (Welford-style for EMA)."""

    def __init__(self, alpha: float = 0.1, warmup_samples: int = 5) -> None:
        self.alpha = alpha
        self.warmup_samples = warmup_samples
        self._ema: float = 0.0
        self._ema_sq: float = 0.0  # EMA of x^2 for variance estimate
        self._n: int = 0

    def update(self, value: float) -> None:
        self._n += 1
        if self._n == 1:
            self._ema = value
            self._ema_sq = value ** 2
        else:
            self._ema = self.alpha * value + (1 - self.alpha) * self._ema
            self._ema_sq = self.alpha * value ** 2 + (1 - self.alpha) * self._ema_sq

    @property
    def mean(self) -> float:
        return self._ema

    @property
    def std(self) -> float:
        """Population standard deviation from EMA of x and EMA of x^2.

        Var(x) = E[x^2] - E[x]^2, clamped to avoid sqrt of negative due to
        floating-point drift.
        """
        variance = max(self._ema_sq - self._ema ** 2, 0.0)
        return math.sqrt(variance)

    @property
    def is_warmed_up(self) -> bool:
        return self._n >= self.warmup_samples


# ---------------------------------------------------------------------------
# Salience engine
# ---------------------------------------------------------------------------

class SalienceEngine:
    """Compute composite salience scores from a stream of ThreatIndicators.

    The node's own position is needed to calculate distance-based terms.
    If not supplied, distances default to 1.0 km / 1000 m.

    Parameters
    ----------
    threshold:
        Score above which the system should transition to DEFENDING.
    ema_alpha:
        Smoothing factor for the trunking-rate EMA.  Lower values give
        more weight to historical data; higher values react faster.
    node_lat, node_lon:
        Geographic position of the SENTINEL-NODE sensor.
    """

    def __init__(
        self,
        threshold: float = 2.5,
        ema_alpha: float = 0.1,
        node_lat: Optional[float] = None,
        node_lon: Optional[float] = None,
    ) -> None:
        self.threshold = threshold
        self.node_lat = node_lat
        self.node_lon = node_lon

        # Per-agency EMA trackers keyed by (agency_prefix, channel)
        self._trunking_stats: Dict[str, _RunningStats] = {}
        self._global_trunking_stats = _RunningStats(alpha=ema_alpha)

        # Track previous M_d for suppression detection.
        # _prev_* holds the value from the LAST completed tick (updated at end of update()).
        # _last_prev_* holds the value from the tick BEFORE the last one — i.e. the
        # "previous" seen from the perspective of check_transition(_with_indicators) which
        # is called AFTER update() returns.  Both sets are needed to correctly detect
        # the DEFENDING→LISTENING direction and the suppression scenario respectively.
        self._prev_mesh_term: float = 0.0
        self._prev_trunking_term: float = 0.0
        self._prev_aviation_term: float = 0.0

        # Stash of the pre-tick previous values, populated by update() and consumed
        # by _check_suppressed_mesh_proxy when called from check_transition*.
        self._last_prev_mesh_term: float = 0.0
        self._last_prev_trunking_term: float = 0.0
        self._last_prev_aviation_term: float = 0.0

        # Current mode
        self._mode: str = "LISTENING"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_mode(self) -> str:
        """Return current operating mode: ``"LISTENING"`` or ``"DEFENDING"``."""
        return self._mode

    def set_mode(self, mode: str) -> None:
        """Allow the state machine to update the engine's mode record."""
        if mode not in ("LISTENING", "DEFENDING"):
            raise ValueError(f"Invalid mode: {mode!r}")
        self._mode = mode

    def update(self, indicators: List[ThreatIndicator]) -> SalienceSnapshot:
        """Process a batch of indicators and return a new SalienceSnapshot.

        Parameters
        ----------
        indicators:
            All ThreatIndicator records received since the last update tick.
            May be empty (returns a near-zero snapshot with EMA decay).

        Returns
        -------
        SalienceSnapshot
            Decomposed score snapshot with all three terms populated.
        """
        edacs = [i for i in indicators if i.channel == "EDACS"]
        adsb = [i for i in indicators if i.channel == "ADS_B"]
        mesh = [i for i in indicators if i.channel == "MESHTASTIC"]

        # Snapshot previous terms BEFORE computing current ones so that
        # failure-flag detection in check_transition / check_transition_with_indicators
        # (called after this method returns) can compare previous vs. current.
        prev_mesh = self._prev_mesh_term
        prev_trunking = self._prev_trunking_term
        prev_aviation = self._prev_aviation_term

        trunking_term = self._compute_trunking_term(edacs)
        aviation_term = self._compute_aviation_term(adsb)
        mesh_term = self._compute_mesh_term(mesh)

        score = trunking_term + aviation_term + mesh_term

        snapshot = SalienceSnapshot(
            snapshot_id=uuid4(),
            timestamp=datetime.now(timezone.utc),
            score=score,
            trunking_term=trunking_term,
            aviation_term=aviation_term,
            mesh_term=mesh_term,
            threshold=self.threshold,
            mode=self._mode,
        )

        # Store current terms as "previous" for the NEXT tick's suppression check.
        # The suppression check for THIS tick uses the prev_* locals captured above.
        self._prev_trunking_term = trunking_term
        self._prev_aviation_term = aviation_term
        self._prev_mesh_term = mesh_term

        # Stash the pre-tick values so _check_suppressed_mesh_proxy (called from
        # check_transition_with_indicators after update() returns) sees them.
        self._last_prev_mesh_term = prev_mesh
        self._last_prev_trunking_term = prev_trunking
        self._last_prev_aviation_term = prev_aviation

        return snapshot

    def check_transition(
        self, snapshot: SalienceSnapshot
    ) -> Optional[ModeTransition]:
        """Evaluate whether a mode transition should occur and return it if so.

        A transition object is returned on every crossing, including when the
        system returns to LISTENING.  The caller (state machine) decides
        whether to honour the transition after applying hysteresis / cooldown.

        Failure flags are populated regardless of direction so analysts can
        examine near-miss events.

        Parameters
        ----------
        snapshot:
            The snapshot just produced by :meth:`update`.

        Returns
        -------
        ModeTransition or None
            None when the score does not cross the current threshold boundary.
        """
        crossing = self._detect_crossing(snapshot.score)
        if crossing is None:
            return None

        from_mode, to_mode = crossing
        failure_flags = self._detect_failure_flags(snapshot)

        transition = ModeTransition(
            transition_id=uuid4(),
            timestamp=snapshot.timestamp,
            from_mode=from_mode,
            to_mode=to_mode,
            salience_at_transition=snapshot.score,
            trigger_snapshot_id=snapshot.snapshot_id,
            failure_flags=failure_flags,
        )
        return transition

    # ------------------------------------------------------------------
    # Score computation
    # ------------------------------------------------------------------

    def _compute_trunking_term(self, edacs_indicators: List[ThreatIndicator]) -> float:
        """Compute W_a * T_d(t).

        T_d(t) is the z-score of the current trunking-message rate relative
        to the per-engine EMA baseline.  W_a is the maximum agency weight
        across all EDACS indicators in this tick (worst-case assumption).

        During warmup (fewer than 5 samples), returns the raw count * default
        weight to avoid division by a near-zero standard deviation.
        """
        rate = float(len(edacs_indicators))
        self._global_trunking_stats.update(rate)

        if not edacs_indicators:
            return 0.0

        # Agency weight: maximum among all indicators this tick
        w_a = max(
            self._agency_weight_for(ind) for ind in edacs_indicators
        )

        if not self._global_trunking_stats.is_warmed_up:
            # Pre-warmup: simple proportional contribution
            return w_a * rate / max(self._global_trunking_stats.mean, 1.0)

        std = self._global_trunking_stats.std
        if std < 1e-6:
            # Effectively constant rate — no anomaly signal
            return 0.0

        z = (rate - self._global_trunking_stats.mean) / std
        # Clamp negative z to zero: below-baseline activity is not a threat
        return w_a * max(z, 0.0)

    def _compute_aviation_term(self, adsb_indicators: List[ThreatIndicator]) -> float:
        """Compute A_p(t) = Σ_i  W_a_i / distance_km_i."""
        total = 0.0
        for ind in adsb_indicators:
            w_a = self._aviation_weight_for(ind)
            dist_km = _safe_distance_km(
                self.node_lat, self.node_lon, ind.latitude, ind.longitude
            )
            total += w_a / dist_km
        return total

    def _compute_mesh_term(self, mesh_indicators: List[ThreatIndicator]) -> float:
        """Compute M_d(t) = Σ_j  node_weight_j / distance_m_j * 1000."""
        total = 0.0
        for ind in mesh_indicators:
            dist_km = _safe_distance_km(
                self.node_lat, self.node_lon, ind.latitude, ind.longitude
            )
            dist_m = dist_km * 1000.0
            # Floor distance to 1 m to prevent extreme values for co-located nodes
            dist_m = max(dist_m, 1.0)
            node_weight = ind.raw_weight
            total += node_weight / dist_m * 1000.0
        return total

    # ------------------------------------------------------------------
    # Weight helpers
    # ------------------------------------------------------------------

    def _agency_weight_for(self, ind: ThreatIndicator) -> float:
        """Resolve agency weight for an EDACS indicator."""
        if ind.raw_weight != 1.0:
            return ind.raw_weight  # caller pre-loaded a specific weight

        subfleet = ind.metadata.get("subfleet_prefix", "")
        if not subfleet and ind.primary_id:
            subfleet = ind.primary_id

        return get_agency_weight(str(subfleet))

    def _aviation_weight_for(self, ind: ThreatIndicator) -> float:
        """Resolve weight for an ADS-B indicator.

        Surveillance ICAO prefixes receive the pre-loaded agency weight;
        everything else receives a reduced base weight of 0.15 to represent
        the low-but-non-zero probability of state aviation not yet in the
        prefix database.
        """
        icao = ind.primary_id or ""
        if is_surveillance_icao(icao):
            return ind.raw_weight if ind.raw_weight != 1.0 else 0.85

        subfleet = ind.metadata.get("subfleet_prefix", "")
        if subfleet:
            return get_agency_weight(str(subfleet))

        return 0.15  # unknown civil aviation baseline

    # ------------------------------------------------------------------
    # Crossing detection
    # ------------------------------------------------------------------

    def _detect_crossing(self, score: float) -> Optional[Tuple[str, str]]:
        """Return (from_mode, to_mode) if the score crosses the threshold."""
        if self._mode == "LISTENING" and score >= self.threshold:
            return ("LISTENING", "DEFENDING")
        if self._mode == "DEFENDING" and score < self.threshold * 0.7:
            return ("DEFENDING", "LISTENING")
        return None

    # ------------------------------------------------------------------
    # Failure flag detection
    # ------------------------------------------------------------------

    def _detect_failure_flags(self, snapshot: SalienceSnapshot) -> List[str]:
        """Inspect the snapshot and recent history for known failure signatures.

        Returns a list of failure-mode constant strings.  An empty list means
        no failure pattern was detected — not that the transition is correct.
        """
        flags: List[str] = []

        # We need the raw indicators; they are not stored on the snapshot.
        # The detection logic here uses the decomposed terms and thresholds
        # as proxies.  Full indicator-level checks are performed in
        # check_transition_with_indicators() for callers that supply them.

        flags.extend(self._check_dense_civilian_proxy(snapshot))
        flags.extend(self._check_aviation_commercial_proxy(snapshot))
        flags.extend(self._check_suppressed_mesh_proxy(snapshot))

        return flags

    def _check_dense_civilian_proxy(self, snapshot: SalienceSnapshot) -> List[str]:
        """Flag FALSE_POSITIVE_DENSE_CIVILIAN when mesh is the dominant term.

        Heuristic: mesh_term > 60 % of total score and trunking + aviation
        terms are below threshold individually.  Full profile checking
        requires indicator-level data; see check_transition_with_indicators().
        """
        if snapshot.score <= 0:
            return []
        mesh_fraction = snapshot.mesh_term / snapshot.score
        trunking_low = snapshot.trunking_term < self.threshold * 0.4
        aviation_low = snapshot.aviation_term < self.threshold * 0.4
        if mesh_fraction > 0.60 and trunking_low and aviation_low:
            return [FALSE_POSITIVE_DENSE_CIVILIAN]
        return []

    def _check_aviation_commercial_proxy(self, snapshot: SalienceSnapshot) -> List[str]:
        """Flag FALSE_POSITIVE_AVIATION_COMMERCIAL when aviation is the dominant term.

        Heuristic: aviation_term > 60 % of total score and other terms are low.
        Full altitude/orbit checks require indicator metadata; see
        check_transition_with_indicators().
        """
        if snapshot.score <= 0:
            return []
        av_fraction = snapshot.aviation_term / snapshot.score
        trunking_low = snapshot.trunking_term < self.threshold * 0.4
        mesh_low = snapshot.mesh_term < self.threshold * 0.4
        if av_fraction > 0.60 and trunking_low and mesh_low:
            return [FALSE_POSITIVE_AVIATION_COMMERCIAL]
        return []

    def _check_suppressed_mesh_proxy(self, snapshot: SalienceSnapshot) -> List[str]:
        """Flag FALSE_NEGATIVE_SUPPRESSED_MESH when mesh drops to zero while
        trunking or aviation remain elevated.

        Suppression is ambiguous: it could mean no mesh nodes are present, or
        it could mean an adversary has jammed the channel.  The flag is raised
        when the previous tick had non-zero mesh and this tick has zero mesh
        with at least one other term elevated — a pattern inconsistent with a
        genuinely quiet scene.

        Implementation note: this method is called AFTER update() returns, so
        ``_prev_mesh_term`` already reflects the CURRENT tick's mesh value.
        We use ``_last_prev_mesh_term`` which was saved inside update() just
        before it computed the current tick's terms — that value is the true
        "previous tick" mesh reading.
        """
        mesh_was_present = self._last_prev_mesh_term > 0.05
        mesh_now_gone = snapshot.mesh_term < 1e-9
        # "Other elevated" uses an absolute floor (0.5) rather than a threshold-relative
        # percentage so the check remains meaningful even when the configured threshold
        # is very high (e.g. during testing with threshold=10.0).  The 0.5 value means
        # at least one other term is contributing meaningfully to the composite score.
        other_elevated = (
            snapshot.trunking_term > 0.5
            or snapshot.aviation_term > 0.5
        )
        if mesh_was_present and mesh_now_gone and other_elevated:
            return [FALSE_NEGATIVE_SUPPRESSED_MESH]
        return []

    # ------------------------------------------------------------------
    # Full-fidelity failure detection (requires raw indicators)
    # ------------------------------------------------------------------

    def check_transition_with_indicators(
        self,
        snapshot: SalienceSnapshot,
        indicators: List[ThreatIndicator],
    ) -> Optional[ModeTransition]:
        """Like check_transition() but with full indicator access for precise
        failure-flag evaluation.

        This method performs exact checks against indicator metadata rather
        than the score-fraction proxies used by check_transition().  The
        state machine calls this variant when indicators are available.
        """
        crossing = self._detect_crossing(snapshot.score)
        if crossing is None:
            return None

        from_mode, to_mode = crossing
        failure_flags: List[str] = []

        adsb = [i for i in indicators if i.channel == "ADS_B"]
        mesh = [i for i in indicators if i.channel == "MESHTASTIC"]

        # --- FALSE_POSITIVE_DENSE_CIVILIAN ---
        # All mesh nodes are "civilian" with no "tactical" tags
        if mesh:
            all_civilian = all(
                ind.metadata.get("profile", "civilian") == "civilian"
                and "tactical" not in ind.tags
                for ind in mesh
            )
            if all_civilian and snapshot.mesh_term > self.threshold * 0.4:
                failure_flags.append(FALSE_POSITIVE_DENSE_CIVILIAN)

        # --- FALSE_POSITIVE_AVIATION_COMMERCIAL ---
        # Aircraft altitude > 5000 ft and no orbit pattern
        for ind in adsb:
            altitude_ft = ind.metadata.get("altitude_ft", 0)
            orbit = ind.metadata.get("orbit_pattern", False)
            if altitude_ft > 5000 and not orbit:
                failure_flags.append(FALSE_POSITIVE_AVIATION_COMMERCIAL)
                break  # one suffices for the flag

        # --- FALSE_NEGATIVE_SUPPRESSED_MESH ---
        # Previous mesh was present; now absent with other terms elevated
        failure_flags.extend(self._check_suppressed_mesh_proxy(snapshot))

        transition = ModeTransition(
            transition_id=uuid4(),
            timestamp=snapshot.timestamp,
            from_mode=from_mode,
            to_mode=to_mode,
            salience_at_transition=snapshot.score,
            trigger_snapshot_id=snapshot.snapshot_id,
            failure_flags=list(dict.fromkeys(failure_flags)),  # deduplicate, preserve order
        )
        return transition
