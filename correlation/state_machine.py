"""
state_machine.py — LISTENING ↔ DEFENDING state machine with cooldown and hysteresis.

SENTINEL-NODE synthetic policy demonstration platform.
All data is fictional; no real RF or hardware is involved.

State semantics
---------------
LISTENING  — baseline monitoring mode; salience score is below threshold.
DEFENDING  — elevated-alert mode; score has crossed the configured threshold.

Transition rules
----------------
LISTENING → DEFENDING : score >= threshold (instantaneous on first crossing)
DEFENDING → LISTENING : score < threshold * 0.7 for 3 consecutive snapshots
                        AND at least 60 seconds have elapsed since entering DEFENDING.

Hysteresis prevents oscillation near the boundary.
Cooldown prevents rapid DEFENDING → LISTENING exits during a sustained operation.

False-positive tracking
-----------------------
Analysts can retrospectively mark a LISTENING→DEFENDING transition as a false
positive via mark_retrospective_fp().  get_false_positive_rate() returns the
fraction of all DEFENDING transitions that have been so marked.
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from adapters.base import ModeTransition, SalienceSnapshot, ThreatIndicator
from correlation.salience import SalienceEngine


# ---------------------------------------------------------------------------
# State constants
# ---------------------------------------------------------------------------

STATE_LISTENING = "LISTENING"
STATE_DEFENDING = "DEFENDING"

_HYSTERESIS_RATIO = 0.7       # must fall below threshold * 0.7 to exit DEFENDING
_HYSTERESIS_CONSECUTIVE = 3   # must stay below hysteresis band for this many ticks
_COOLDOWN_SECONDS = 60        # minimum seconds in DEFENDING before returning to LISTENING


class SentinelStateMachine:
    """Full LISTENING ↔ DEFENDING state machine for the SENTINEL-NODE platform.

    Parameters
    ----------
    threshold:
        Salience score above which the node transitions to DEFENDING.
    ema_alpha:
        Smoothing factor passed to :class:`SalienceEngine`.
    node_lat, node_lon:
        Geographic position of the sensor node (optional; used for distance
        calculations inside :class:`SalienceEngine`).
    """

    def __init__(
        self,
        threshold: float = 2.5,
        ema_alpha: float = 0.1,
        node_lat: Optional[float] = None,
        node_lon: Optional[float] = None,
    ) -> None:
        self.threshold = threshold
        self._engine = SalienceEngine(
            threshold=threshold,
            ema_alpha=ema_alpha,
            node_lat=node_lat,
            node_lon=node_lon,
        )

        # Current state
        self._state: str = STATE_LISTENING

        # Hysteresis counter — increments each tick score < hysteresis_threshold
        self._below_hysteresis_count: int = 0
        self._hysteresis_threshold: float = threshold * _HYSTERESIS_RATIO

        # Cooldown tracking
        self._defending_since: Optional[datetime] = None

        # Transition log (full history)
        self._history: List[ModeTransition] = []

        # Retrospective FP annotations keyed by transition_id
        self._retrospective_fps: Dict[UUID, str] = {}

        # Count of LISTENING→DEFENDING transitions (total DEFENDING entries)
        self._defending_transition_count: int = 0

    # ------------------------------------------------------------------
    # Primary interface
    # ------------------------------------------------------------------

    def step(
        self,
        indicators: List[ThreatIndicator],
    ) -> Tuple[str, SalienceSnapshot, Optional[ModeTransition]]:
        """Advance the state machine by one tick.

        Parameters
        ----------
        indicators:
            All ThreatIndicator records for this time window.

        Returns
        -------
        tuple of (current_state, snapshot, transition_or_None)
            ``current_state`` is the state *after* processing this tick.
            ``transition_or_None`` is a :class:`ModeTransition` if a state
            change occurred, otherwise None.
        """
        snapshot = self._engine.update(indicators)
        transition = self._evaluate_transition(snapshot, indicators)

        if transition is not None:
            self._apply_transition(transition)
            snapshot.mode = self._state

        return self._state, snapshot, transition

    # ------------------------------------------------------------------
    # Transition evaluation
    # ------------------------------------------------------------------

    def _evaluate_transition(
        self,
        snapshot: SalienceSnapshot,
        indicators: List[ThreatIndicator],
    ) -> Optional[ModeTransition]:
        """Decide whether a state transition should occur this tick.

        Applies hysteresis, cooldown, and failure-flag detection.
        """
        score = snapshot.score
        now = snapshot.timestamp

        if self._state == STATE_LISTENING:
            return self._evaluate_from_listening(score, snapshot, indicators)
        else:
            return self._evaluate_from_defending(score, snapshot, indicators, now)

    def _evaluate_from_listening(
        self,
        score: float,
        snapshot: SalienceSnapshot,
        indicators: List[ThreatIndicator],
    ) -> Optional[ModeTransition]:
        """Evaluate LISTENING → DEFENDING crossing."""
        # Reset hysteresis counter whenever we are in LISTENING
        self._below_hysteresis_count = 0

        if score < self.threshold:
            return None

        # Threshold crossed — build transition with full failure-flag fidelity
        transition = self._engine.check_transition_with_indicators(snapshot, indicators)
        if transition is None:
            # Fallback: construct manually (should not happen since we confirmed crossing)
            transition = ModeTransition(
                transition_id=uuid4(),
                timestamp=snapshot.timestamp,
                from_mode=STATE_LISTENING,
                to_mode=STATE_DEFENDING,
                salience_at_transition=score,
                trigger_snapshot_id=snapshot.snapshot_id,
                failure_flags=[],
            )

        self._defending_transition_count += 1
        return transition

    def _evaluate_from_defending(
        self,
        score: float,
        snapshot: SalienceSnapshot,
        indicators: List[ThreatIndicator],
        now: datetime,
    ) -> Optional[ModeTransition]:
        """Evaluate DEFENDING → LISTENING crossing with hysteresis and cooldown."""
        if score >= self._hysteresis_threshold:
            # Still above hysteresis band — reset counter, stay DEFENDING
            self._below_hysteresis_count = 0
            return None

        # Score is below the hysteresis band
        self._below_hysteresis_count += 1

        if self._below_hysteresis_count < _HYSTERESIS_CONSECUTIVE:
            # Need more consecutive below-band ticks
            return None

        # Check cooldown
        if self._defending_since is not None:
            elapsed = (now - self._defending_since).total_seconds()
            if elapsed < _COOLDOWN_SECONDS:
                # Still within cooldown window
                return None

        # All conditions met — build return-to-LISTENING transition
        transition = self._engine.check_transition_with_indicators(snapshot, indicators)
        if transition is None:
            transition = ModeTransition(
                transition_id=uuid4(),
                timestamp=snapshot.timestamp,
                from_mode=STATE_DEFENDING,
                to_mode=STATE_LISTENING,
                salience_at_transition=score,
                trigger_snapshot_id=snapshot.snapshot_id,
                failure_flags=[],
            )

        return transition

    # ------------------------------------------------------------------
    # State application
    # ------------------------------------------------------------------

    def _apply_transition(self, transition: ModeTransition) -> None:
        """Update internal state and record the transition in history."""
        self._state = transition.to_mode
        self._engine.set_mode(self._state)

        if self._state == STATE_DEFENDING:
            self._defending_since = transition.timestamp
            self._below_hysteresis_count = 0
        elif self._state == STATE_LISTENING:
            self._defending_since = None
            self._below_hysteresis_count = 0

        self._history.append(transition)

    # ------------------------------------------------------------------
    # History and analytics
    # ------------------------------------------------------------------

    def get_history(self) -> List[ModeTransition]:
        """Return a copy of the full transition log in chronological order."""
        return list(self._history)

    def get_false_positive_rate(self) -> float:
        """Return the fraction of DEFENDING transitions retrospectively marked as FP.

        Returns 0.0 if no DEFENDING transitions have occurred.

        A "DEFENDING transition" is any LISTENING→DEFENDING change.  Analysts
        retrospectively annotate these via :meth:`mark_retrospective_fp`.
        """
        if self._defending_transition_count == 0:
            return 0.0

        fp_count = sum(
            1 for t in self._history
            if t.from_mode == STATE_LISTENING
            and t.to_mode == STATE_DEFENDING
            and t.retrospective_fp
        )
        return fp_count / self._defending_transition_count

    def mark_retrospective_fp(self, transition_id: UUID, reason: str) -> None:
        """Mark a LISTENING→DEFENDING transition as a retrospective false positive.

        This is an analyst annotation and does not affect current state.

        Parameters
        ----------
        transition_id:
            UUID of the :class:`ModeTransition` to annotate.
        reason:
            Human-readable explanation, e.g. ``"CONCERT_EVENT_2026-06-04"``.

        Raises
        ------
        KeyError
            If no transition with the given ID exists in the history.
        ValueError
            If the transition was not a LISTENING→DEFENDING transition (only
            those represent decisions that can be false positives).
        """
        for t in self._history:
            if t.transition_id == transition_id:
                if t.from_mode != STATE_LISTENING or t.to_mode != STATE_DEFENDING:
                    raise ValueError(
                        f"Transition {transition_id} is {t.from_mode}→{t.to_mode}; "
                        "only LISTENING→DEFENDING transitions can be false positives."
                    )
                t.retrospective_fp = True
                t.fp_reason = reason
                self._retrospective_fps[transition_id] = reason
                return

        raise KeyError(f"No transition with id {transition_id} found in history.")

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def state(self) -> str:
        """Current state string."""
        return self._state

    @property
    def defending_since(self) -> Optional[datetime]:
        """Timestamp when the current DEFENDING episode began, or None."""
        return self._defending_since

    @property
    def total_transitions(self) -> int:
        """Total number of state transitions recorded."""
        return len(self._history)

    @property
    def defending_entry_count(self) -> int:
        """Number of LISTENING→DEFENDING transitions."""
        return self._defending_transition_count

    def cooldown_remaining(self, now: Optional[datetime] = None) -> float:
        """Seconds of cooldown remaining in DEFENDING, or 0.0 if not applicable."""
        if self._state != STATE_DEFENDING or self._defending_since is None:
            return 0.0
        if now is None:
            now = datetime.now(timezone.utc)
        elapsed = (now - self._defending_since).total_seconds()
        return max(0.0, _COOLDOWN_SECONDS - elapsed)

    def __repr__(self) -> str:
        return (
            f"SentinelStateMachine(state={self._state!r}, "
            f"threshold={self.threshold}, "
            f"transitions={self.total_transitions}, "
            f"fp_rate={self.get_false_positive_rate():.2%})"
        )
