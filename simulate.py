"""
simulate.py -- SENTINEL-NODE South Minneapolis Policy Demonstration

Entrypoint for the synthetic SENTINEL-NODE demonstration intended for
policymaker audiences.  Runs a scripted scenario sequence showing:

  Phase 0 -- Sensor calibration (EMA warmup, 5 quiet ticks)
  Phase 1 -- False positive: outdoor concert floods all three channels,
             triggering DEFENDING; analyst marks it retrospectively
  Phase 2 -- Main scenario: EDACS tactical surge + ADS-B surveillance
             orbit + active Meshtastic spotters drive salience above
             threshold, triggering DEFENDING mode and alert dispatch
  Phase 3 -- GhostTrace deception analysis: disruption metrics, burst
             sample, and failure-mode catalogue including
             COLLATERAL_PRIVACY_HARM for bystander OUI cloning
  Phase 4 -- Policy impact report written to policy_brief_<date>.md

Architecture note: Phases 1 and 2 use separate SentinelStateMachine
instances so the real-wall-clock DEFENDING cooldown (60 s) does not
bleed between the two scenarios when the simulation runs in milliseconds.
Both machines contribute snapshots/transitions to the combined policy
report record.

All data is fictional.  No real RF hardware, network infrastructure,
or surveillance systems are involved.  See DISCLAIMER.md.
"""

import logging
import random
import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from adapters.base import AlertRecord, ModeTransition, SalienceSnapshot
from adapters.normalizer import SentinelNormalizer
from correlation.state_machine import SentinelStateMachine
from defend.ghost_trace import GhostTraceSimulator
from defend.policy_report import PolicyReportGenerator
from defend.shroud_speak import OnionAddressRotator, ShroudSpeakAlert

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# South Minneapolis sensor node position
NODE_LAT: float = 44.9329
NODE_LON: float = -93.2683

# Scenario wall-clock start: 2026-06-04 20:00 CDT = 2026-06-05 01:00 UTC
_SIM_START = datetime(2026, 6, 5, 1, 0, 0, tzinfo=timezone.utc)
_TICK = timedelta(minutes=5)

# Ed25519 demo signing key -- 32 zero bytes, hex encoded.
# Not secret.  Not used in any real deployment.  For structure demonstration only.
_DEMO_KEY_HEX = "00" * 32

_WIDTH = 72


# ---------------------------------------------------------------------------
# Display utilities (ASCII-only for terminal compatibility)
# ---------------------------------------------------------------------------

def _banner(text: str) -> None:
    print()
    print("=" * _WIDTH)
    print(f"  {text}")
    print("=" * _WIDTH)


def _section(title: str, subtitle: str = "") -> None:
    print()
    print("-" * _WIDTH)
    print(f"  {title}")
    if subtitle:
        print(f"  {subtitle}")
    print("-" * _WIDTH)


def _wrap(text: str, indent: int = 2) -> None:
    prefix = " " * indent
    for line in textwrap.wrap(text.strip(), width=_WIDTH - indent):
        print(prefix + line)


def _score_bar(score: float, threshold: float = 2.5) -> str:
    max_display = threshold * 1.6
    filled = int(min(score / max_display, 1.0) * 34)
    bar = "#" * filled + "." * (34 - filled)
    alarm = " *** THRESHOLD CROSSED" if score >= threshold else ""
    return f"[{bar}] {score:6.3f}{alarm}"


def _cdt(utc: datetime) -> str:
    """Format UTC time as CDT (UTC-5 for demo, close enough to CDT)."""
    return (utc - timedelta(hours=5)).strftime("%H:%M CDT")


def _print_tick(
    clock: datetime,
    label: str,
    indicator_count: int,
    snap: SalienceSnapshot,
    state: str,
    transition: Optional[ModeTransition] = None,
) -> None:
    print(f"\n  {_cdt(clock)}  {label}")
    print(f"  Salience  {_score_bar(snap.score)}  (threshold 2.500)")
    print(f"  State     {state:<12s}  Indicators: {indicator_count:2d}")
    print(
        f"  Terms     trunking={snap.trunking_term:+.3f}  "
        f"aviation={snap.aviation_term:+.3f}  "
        f"mesh={snap.mesh_term:+.3f}"
    )
    if transition:
        flags = ", ".join(transition.failure_flags) if transition.failure_flags else "none"
        print(
            f"  TRANSITION  {transition.from_mode} -> {transition.to_mode}"
            f"  failure_flags=[{flags}]"
        )


# ---------------------------------------------------------------------------
# Duck-typed record for PolicyReportGenerator
# ---------------------------------------------------------------------------

class _SimRecord:
    """Accumulates snapshots and transitions in the shape PolicyReportGenerator expects."""

    def __init__(self) -> None:
        self.snapshots: List[SalienceSnapshot] = []
        self.transitions: List[ModeTransition] = []


def _new_sm() -> SentinelStateMachine:
    """Return a fresh state machine at the node's position."""
    return SentinelStateMachine(
        threshold=2.5,
        ema_alpha=0.1,
        node_lat=NODE_LAT,
        node_lon=NODE_LON,
    )


def _warm_up(
    sm: SentinelStateMachine,
    normalizer: SentinelNormalizer,
    record: _SimRecord,
    clock: datetime,
    n: int = 5,
) -> datetime:
    """Run n quiet calibration ticks.  Returns the advanced clock."""
    for _ in range(n):
        ind = (
            normalizer.generate("EDACS", "quiet_period")
            + normalizer.generate("ADS_B", "no_aircraft", node_lat=NODE_LAT, node_lon=NODE_LON)
            + normalizer.generate(
                "MESHTASTIC", "quiet_mesh", node_lat=NODE_LAT, node_lon=NODE_LON
            )
        )
        state, snap, trans = sm.step(ind)
        record.snapshots.append(snap)
        if trans:
            record.transitions.append(trans)
        clock += _TICK
    return clock


# ---------------------------------------------------------------------------
# Simulation
# ---------------------------------------------------------------------------

def run() -> None:
    # Fix the random seed so demonstrations are reproducible
    random.seed(42)

    _banner("SENTINEL-NODE  --  South Minneapolis Policy Demonstration")
    print()
    _wrap(
        "This demonstration runs a scripted synthetic scenario at a South Minneapolis "
        "sensor node (44.93 N, 93.27 W).  The system monitors three data channels "
        "simultaneously: EDACS trunked radio, ADS-B aircraft position reports, and "
        "Meshtastic LoRa mesh traffic.  All data is generated by simulation.  No "
        "hardware, radio transmission, or network communication is involved."
    )
    print()
    _wrap(
        "Audience note: the salience score is a statistical signal, not a judgment.  "
        "Its false positive characteristics are demonstrated in Phase 1.  The "
        "GhostTrace failure modes in Phase 3 show harms created by the counter-"
        "surveillance layer itself, independent of the surveillance it opposes."
    )

    normalizer = SentinelNormalizer()

    # Combined record across both phase SMs -- collected for the policy report
    record = _SimRecord()
    alert_log: List[AlertRecord] = []
    rotator = OnionAddressRotator()

    clock = _SIM_START

    # =========================================================================
    # Phase 0 -- EMA calibration (feeds into Phase 1 SM)
    # =========================================================================
    _section("PHASE 0 -- Sensor Calibration", "20:00 - 20:20 CDT (simulated)")
    _wrap(
        "The salience engine's exponential moving average requires five observation "
        "windows to establish a stable baseline.  During calibration the node "
        "ingests ambient quiet conditions with no anomalies present."
    )

    sm_fp = _new_sm()   # Used for Phase 1 FP demonstration
    clock = _warm_up(sm_fp, normalizer, record, clock, n=5)

    last_snap = record.snapshots[-1]
    print(f"\n  Calibration complete.  Baseline established over 5 windows.")
    print(f"  Current state: {sm_fp.state}   Salience: {last_snap.score:.4f}")

    # =========================================================================
    # Phase 1 -- False positive demonstration
    # =========================================================================
    _section(
        "PHASE 1 -- False Positive: Outdoor Concert",
        "20:25 CDT (simulated)",
    )
    _wrap(
        "A large outdoor music festival in the adjacent corridor floods all three "
        "channels: Meshtastic mesh from attendees, a commercial departure from MSP "
        "airport overhead, and routine municipal EDACS radio.  None of this activity "
        "is a surveillance operation.  This phase demonstrates the false positive risk "
        "inherent in compound multi-channel salience scoring."
    )

    fp_transition_id = None

    for tick_label in [
        "Concert peak -- dense civilian signals",
        "Concert continues (T+5)",
    ]:
        ind = (
            normalizer.generate("EDACS", "routine_patrol")
            + normalizer.generate(
                "ADS_B", "commercial_overpass", node_lat=NODE_LAT, node_lon=NODE_LON
            )
            + normalizer.generate(
                "MESHTASTIC", "dense_civilian", node_lat=NODE_LAT, node_lon=NODE_LON
            )
        )
        state, snap, trans = sm_fp.step(ind)
        record.snapshots.append(snap)
        if trans:
            record.transitions.append(trans)

        _print_tick(clock, tick_label, len(ind), snap, state, trans)

        if trans and trans.to_mode == "DEFENDING" and fp_transition_id is None:
            fp_transition_id = trans.transition_id
            print()
            _wrap(
                ">>> FALSE POSITIVE DETECTED: system entered DEFENDING mode in "
                "response to civilian concert traffic.  Failure flag: "
                "FALSE_POSITIVE_DENSE_CIVILIAN.  An analyst reviewing the "
                "timeline marks this transition as a non-threat event."
            )
            sm_fp.mark_retrospective_fp(fp_transition_id, "CONCERT_SOUTHMPLS_2026-06-04")

        clock += _TICK

    if fp_transition_id is None:
        print()
        _wrap(
            "In this run, EMA dampening absorbed the civilian burst without "
            "triggering a mode transition.  This illustrates the smoothing "
            "trade-off: higher alpha reduces false positives at the cost of "
            "increased detection latency for real threats."
        )

    print()
    if fp_transition_id is not None:
        _wrap(
            "The false positive demonstrates a structural limitation: the system "
            "cannot distinguish a music festival from a tactical operation from the "
            "signal profile alone.  Analyst review is required after the fact.  "
            "Phase 2 shows what a genuine tactical escalation looks like on the "
            "same sensor."
        )

    # =========================================================================
    # Phase 2 -- Main scenario: tactical escalation (fresh SM instance)
    # =========================================================================
    _section(
        "PHASE 2 -- Main Scenario: Tactical Escalation",
        "21:00 CDT (simulated)",
    )
    _wrap(
        "Phase 2 uses a fresh sensor instance to avoid carryover from Phase 1.  "
        "This models a second sensor node or a post-event reset.  The following "
        "sequence represents the SENTINEL-NODE reference scenario: a staged "
        "tactical deployment observed simultaneously across all three channels.  "
        "Timestamps are relative to the threshold crossing (T-0)."
    )

    sm_main = _new_sm()

    # Warm up the main SM quietly before the scenario
    print("\n  [Calibrating main sensor -- 5 quiet windows]")
    clock = _warm_up(sm_main, normalizer, record, clock, n=5)
    last_snap = record.snapshots[-1]
    print(f"  Calibration complete.  Salience: {last_snap.score:.4f}")

    main_scenarios = [
        (
            "T-15",
            "routine_patrol",
            "no_aircraft",
            "quiet_mesh",
            "Routine activity only.  Periodic EDACS talkgroup grants on standard "
            "municipal channels.  No aircraft, sparse mesh.",
        ),
        (
            "T-10",
            "routine_patrol",
            "commercial_overpass",
            "active_spotters",
            "Three Meshtastic nodes appear within 300 m (1-hop range).  Commercial "
            "aircraft overhead -- ambiguous at this observation window.",
        ),
        (
            "T-5",
            "tactical_surge",
            "surveillance_pattern",
            "active_spotters",
            "EDACS tactical subfleet surge: talkgroups 200xx-209x dominate the "
            "control channel.  Aircraft enters an orbit pattern consistent with "
            "aerial surveillance.  All three terms now elevated.",
        ),
        (
            "T-0",
            "tactical_surge",
            "surveillance_pattern",
            "active_spotters",
            "Peak.  EDACS event density in 90th percentile.  Aircraft in sustained "
            "loiter.  Meshtastic spotter density holding.  Threshold crossing expected.",
        ),
    ]

    defending_triggered = False

    for label, edacs_sc, adsb_sc, mesh_sc, description in main_scenarios:
        ind = (
            normalizer.generate("EDACS", edacs_sc)
            + normalizer.generate("ADS_B", adsb_sc, node_lat=NODE_LAT, node_lon=NODE_LON)
            + normalizer.generate(
                "MESHTASTIC", mesh_sc, node_lat=NODE_LAT, node_lon=NODE_LON
            )
        )
        state, snap, trans = sm_main.step(ind)
        record.snapshots.append(snap)
        if trans:
            record.transitions.append(trans)

        _print_tick(clock, label, len(ind), snap, state, trans)
        _wrap(description)

        if trans and trans.to_mode == "DEFENDING" and not defending_triggered:
            defending_triggered = True

            onion = rotator.current_address()
            alert_obj = ShroudSpeakAlert(snap, onion, ttl_seconds=300)
            alert_rec = alert_obj.pack(_DEMO_KEY_HEX)
            alert_rec.dispatched = True
            alert_log.append(alert_rec)

            ks_bytes = rotator.sync_key_rotation_payload()

            print()
            _w = _WIDTH - 6
            print("  +" + "-" * _w + "+")
            def _box_line(s: str) -> str:
                return "  | " + s + " " * (_w - 2 - len(s)) + " |"
            print(_box_line("DEFENDING MODE ACTIVATED"))
            print(_box_line("Salience threshold crossed.  Counter-measures initiated."))
            print("  +" + "-" * _w + "+")
            print(f"\n  Alert staged for dispatch via Tor hidden service")
            print(f"  Ephemeral .onion    : {onion[:44]}...")
            print(
                f"  Key-rotation payload: {len(ks_bytes)} bytes  "
                "(Fernet-encrypted, for LoRa SX1262 broadcast)"
            )
            print(f"  Ed25519 signature   : demo key (32 zero bytes -- not secret)")

        clock += _TICK

    # Resolution
    print()
    _wrap(
        "Tactical activity subsides.  The system requires three consecutive "
        "below-hysteresis windows (score < 1.75) plus a 60-second cooldown "
        "before returning to LISTENING."
    )

    for i in range(12):
        ind = (
            normalizer.generate("EDACS", "quiet_period")
            + normalizer.generate(
                "ADS_B", "no_aircraft", node_lat=NODE_LAT, node_lon=NODE_LON
            )
            + normalizer.generate(
                "MESHTASTIC", "quiet_mesh", node_lat=NODE_LAT, node_lon=NODE_LON
            )
        )
        state, snap, trans = sm_main.step(ind)
        record.snapshots.append(snap)
        if trans:
            record.transitions.append(trans)
            print(
                f"  {_cdt(clock)}  {trans.from_mode} -> {trans.to_mode}"
                f"  score={snap.score:.3f}"
            )
        clock += _TICK
        if state == "LISTENING":
            break

    print(f"\n  Final state: {state}   Score: {snap.score:.4f}")
    if state == "DEFENDING":
        print(
            "  [Note: the 60-second cooldown uses real wall-clock time.  In a live "
            "deployment the system returns to LISTENING within 60 s of the score "
            "dropping below hysteresis.  Simulation runs complete in milliseconds.]"
        )
    total_defending = sm_fp.defending_entry_count + sm_main.defending_entry_count
    total_fp = sum(1 for t in record.transitions if t.retrospective_fp)
    print(
        f"  Combined DEFENDING entries: {total_defending}"
        f"   Retrospective FP transitions: {total_fp}"
    )

    # =========================================================================
    # Phase 3 -- GhostTrace deception analysis
    # =========================================================================
    _section("PHASE 3 -- GhostTrace Deception Engine Analysis")
    _wrap(
        "When SENTINEL-NODE entered DEFENDING mode, GhostTrace activated.  GhostTrace "
        "is a counter-surveillance technique where an ESP32-C6 device injects synthetic "
        "802.11 frames to inflate the apparent local device count, degrading WIDS-based "
        "checkpoint-to-checkpoint correlation.  The following analysis is entirely "
        "synthetic.  No frames were transmitted.  No hardware was accessed."
    )

    ghost = GhostTraceSimulator(target_device_count=12, tx_rate_mean=0.083)

    # Simulate passive sniff of bystander OUI prefixes before activation.
    # OUI prefixes from the IEEE public registry (Apple, Samsung, Google Pixel).
    bystander_devices = [
        {"oui": "F4:F1:5A"},   # Apple iPhone
        {"oui": "BC:14:85"},   # Samsung Galaxy
        {"oui": "F4:60:E2"},   # Google Pixel
        {"oui": "3C:22:FB"},   # Apple
        {"oui": "F4:42:8F"},   # Samsung
        {"oui": "4C:BC:98"},   # Google
        {"oui": "A4:C3:F0"},   # Apple
        {"oui": "8C:C8:4B"},   # Samsung
    ]
    ghost.sniff_environment(bystander_devices)
    burst = ghost.generate_decoy_burst(duration_seconds=30)

    print(f"\n  Virtual device pool       : {ghost.target_device_count} devices")
    print(f"  Bystander OUIs sniffed    : {len(bystander_devices)}")
    print(f"  Synthetic frames (30s)    : {len(burst)}")
    print()
    print("  Sample burst output (first 3 frames):")
    for frame in burst[:3]:
        print(
            f"    {frame['mac']}  seq={frame['sequence_number']:04d}  "
            f"rssi={frame['rssi_dbm']:+d} dBm  type={frame['frame_type']}"
        )

    # Checkpoint correlation disruption metrics
    real_count = 25       # attendees at the demonstration
    checkpoint_count = 4  # WIDS observation windows
    d = ghost.compute_correlation_disruption(real_count, checkpoint_count)

    print()
    print("  Checkpoint Correlation Disruption Metrics")
    print("  " + "-" * 48)
    print(f"  Real devices present          : {real_count}")
    print(f"  GhostTrace virtual devices    : {ghost.target_device_count}")
    print(f"  Effective anonymity set       : {d['anonymity_set_size']}")
    print(f"  Baseline correlation conf.    : {d['baseline_confidence']:.1%}")
    print(f"  Post-injection confidence     : {d['post_injection_confidence']:.1%}")
    print(f"  Disruption ratio              : {d['disruption_ratio']:.1%}")
    print()
    _wrap(
        f"Before GhostTrace, a checkpoint correlation system tracking {real_count} "
        f"attendees across {checkpoint_count} observation windows achieves "
        f"{d['baseline_confidence']:.0%} cross-checkpoint identity confidence.  "
        f"After injection of {ghost.target_device_count} virtual devices, the "
        f"system must distinguish 1 real device in an anonymity set of "
        f"{d['anonymity_set_size']}, degrading confidence to "
        f"{d['post_injection_confidence']:.0%} -- a {d['disruption_ratio']:.0%} "
        f"reduction in surveillance effectiveness."
    )

    # Failure mode catalogue
    print()
    print("  GhostTrace Failure Modes:")
    failure_modes = ghost.failure_modes()
    for fm in failure_modes:
        harm_tag = "  <-- SECOND-ORDER HARM" if fm.get("second_order_harm") else ""
        print(f"    [{fm['severity']:8s}] {fm['id']}{harm_tag}")

    print()
    _wrap(
        "COLLATERAL PRIVACY HARM -- highlighted for policymakers: GhostTrace "
        "sniffed OUI prefixes from " + str(len(bystander_devices)) + " real bystander "
        "devices before generating its synthetic frame burst.  If a law-enforcement "
        "passive-capture system retained those synthetic frames alongside real "
        "traffic, each bystander acquired a false presence record -- an association "
        "between their device identity and this event, at times they may not have "
        "been physically present.  They have no mechanism to know GhostTrace was "
        "operating.  They cannot obtain the capture data.  They have no forensic "
        "basis to distinguish synthetic frames attributed to their OUI from real "
        "ones.  This harm is created by the counter-surveillance system, not by "
        "the surveillance system it opposes."
    )

    # =========================================================================
    # Phase 4 -- Policy impact report
    # =========================================================================
    _section("PHASE 4 -- Policy Impact Report")

    report = PolicyReportGenerator(
        state_machine=record,
        ghost_trace_sim=ghost,
        alert_log=alert_log,
    )
    data = report.generate()
    md = report.to_markdown()

    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    out_path = Path(__file__).parent / f"policy_brief_{date_str}.md"
    out_path.write_text(md, encoding="utf-8")

    summary = data["summary"]
    collateral = data["collateral_harms_count"]

    print(f"\n  Policy brief written to: {out_path.name}")
    print()
    print("  Simulation Summary")
    print("  " + "-" * 50)
    print(f"  Observation windows (combined)  : {len(record.snapshots)}")
    print(f"  Mode transitions (combined)     : {summary['total_transitions']}")
    print(f"  DEFENDING entries (Phase 1 FP)  : {sm_fp.defending_entry_count}")
    print(f"  DEFENDING entries (Phase 2 real): {sm_main.defending_entry_count}")
    print(f"  False-positive transitions      : {summary['false_positive_transitions']}")
    print(f"  Alerts dispatched               : {summary['total_alerts_dispatched']}")
    print(f"  Bystander OUI clone estimate    : {collateral['estimated_bystander_oui_clones']}")
    print(f"  Second-order effects            : {len(data['second_order_effects'])}")
    print(f"  Third-order effects             : {len(data['third_order_effects'])}")
    print(f"  GhostTrace failure modes        : {len(data['ghost_trace_failure_modes'])}")

    # =========================================================================
    # End
    # =========================================================================
    _banner("End of Demonstration")
    print()
    _wrap(
        "The demonstration showed: (1) how compound multi-channel salience scoring "
        "detects tactical radio deployments; (2) that identical signal profiles arise "
        "from civilian events, producing false positives that require retrospective "
        "analyst review; (3) that GhostTrace's OUI-cloning mechanism creates privacy "
        "violations for uninvolved bystanders regardless of whether it succeeds as a "
        "counter-measure; and (4) that each technology layer in this arms race "
        "introduces collateral effects not visible to either side's operators."
    )
    print()
    _wrap(
        "The full policy brief with second- and third-order effect analysis, "
        f"false-positive event detail, and GhostTrace failure mode catalogue "
        f"is in: {out_path.name}"
    )
    print()


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    run()
