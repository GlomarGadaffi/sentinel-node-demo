"""
policy_report.py — Policy impact report generator for SENTINEL-NODE.

SENTINEL-NODE synthetic policy demonstration platform.
All data is fictional and used solely to demonstrate system behavior
under simulated enforcement pressure for policymaker education.

This module aggregates state-machine telemetry, GhostTrace simulation
outputs, and alert logs into a structured policy impact report.  The
report is designed to be readable by non-technical policymakers and
highlights:

  1. Operational summary: how the system spent its time and how many
     mode transitions were false positives.
  2. Second-order effects: harms downstream of the surveillance
     infrastructure being responded to, not downstream of SENTINEL-NODE.
  3. Third-order effects: arms-race dynamics that each layer of
     technology introduces, including harms introduced by the
     counter-surveillance layer itself.
  4. GhostTrace failure modes and bystander harm estimates.

The report is structured for machine consumption (generate() → dict)
and for human consumption (to_markdown() → str).
"""

from __future__ import annotations

import math
import textwrap
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from adapters.base import AlertRecord, ModeTransition, SalienceSnapshot
from defend.ghost_trace import GhostTraceSimulator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _fmt_duration(seconds: float) -> str:
    """Format a duration in seconds as a human-readable string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f}m"
    hours = minutes / 60
    return f"{hours:.2f}h"


def _safe_ratio(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


# ---------------------------------------------------------------------------
# PolicyReportGenerator
# ---------------------------------------------------------------------------

class PolicyReportGenerator:
    """Generates a structured policy impact report from a SENTINEL-NODE simulation run.

    Parameters
    ----------
    state_machine:
        The running or completed state machine instance.  Must expose:
        - ``snapshots``: List[SalienceSnapshot]
        - ``transitions``: List[ModeTransition]
        Accepts any duck-typed object with those attributes so the report
        generator does not depend on a concrete state-machine class.
    ghost_trace_sim:
        A GhostTraceSimulator instance whose device pool reflects the
        simulation run.
    alert_log:
        Ordered list of AlertRecord objects produced during the run.
    """

    def __init__(
        self,
        state_machine: Any,
        ghost_trace_sim: GhostTraceSimulator,
        alert_log: List[AlertRecord],
    ) -> None:
        self._sm = state_machine
        self._gt = ghost_trace_sim
        self._alert_log = alert_log

    # ------------------------------------------------------------------
    # Internal computations
    # ------------------------------------------------------------------

    def _snapshots(self) -> List[SalienceSnapshot]:
        return getattr(self._sm, "snapshots", [])

    def _transitions(self) -> List[ModeTransition]:
        return getattr(self._sm, "transitions", [])

    def _compute_time_in_mode(self) -> Dict[str, float]:
        """Estimate total seconds spent in LISTENING and DEFENDING.

        Uses consecutive snapshot timestamps as a proxy for wall-clock time.
        If fewer than two snapshots exist, returns zeroes.
        """
        snaps = self._snapshots()
        time_listening = 0.0
        time_defending = 0.0

        for i in range(1, len(snaps)):
            prev = snaps[i - 1]
            curr = snaps[i]
            try:
                delta = (curr.timestamp - prev.timestamp).total_seconds()
            except Exception:  # noqa: BLE001
                delta = 0.0
            if prev.mode == "LISTENING":
                time_listening += delta
            elif prev.mode == "DEFENDING":
                time_defending += delta

        return {"LISTENING": time_listening, "DEFENDING": time_defending}

    def _false_positive_events(self) -> List[ModeTransition]:
        """Return all transitions marked as retrospective false positives."""
        return [t for t in self._transitions() if getattr(t, "retrospective_fp", False)]

    def _fp_rate(self) -> float:
        """False-positive rate: FP transitions / total transitions."""
        total = len(self._transitions())
        fp_count = len(self._false_positive_events())
        return _safe_ratio(fp_count, total)

    def _estimate_bystander_oui_clones(self) -> int:
        """Estimate number of bystander OUI clone events from alert log.

        Each AlertRecord that was dispatched during a DEFENDING period
        implies a GhostTrace burst was active.  We multiply by the
        simulator's virtual device count as an upper-bound estimate of
        clone events (each virtual device clones one OUI per burst).
        This is a conservative model — real deployment would multiply
        by burst duration and per-device frame rate.
        """
        defending_alerts = sum(
            1 for a in self._alert_log if not a.dispatch_error
        )
        return defending_alerts * self._gt.target_device_count

    # ------------------------------------------------------------------
    # Second-order effects catalogue (surveillance → community harms)
    # ------------------------------------------------------------------

    @staticmethod
    def _second_order_effects() -> List[dict]:
        """Downstream harms caused by the surveillance infrastructure itself.

        These are not harms caused by SENTINEL-NODE or GhostTrace — they
        are the policy context that motivates counter-surveillance deployment.
        """
        return [
            {
                "effect": "chilling_effect_on_assembly",
                "category": "Civil Liberties",
                "description": (
                    "Persistent aerial and ground-level surveillance of public "
                    "gatherings deters participation regardless of legal protections.  "
                    "People who observe surveillance aircraft or ground WIDS equipment "
                    "at a location frequently choose not to attend, not because their "
                    "intended activity is unlawful, but because the cost of being "
                    "identified as present — even without doing anything wrong — is "
                    "perceived as too high.  This chilling effect is empirically "
                    "documented and operates independently of whether any individual "
                    "is ever charged with a crime."
                ),
                "mechanism": "Rational deterrence under identity-disclosure risk",
                "affected_population": "All potential participants in lawful public assembly",
                "measurable_indicator": "Reduced turnout at surveilled events vs matched controls",
            },
            {
                "effect": "economic_disruption",
                "category": "Economic Impact",
                "description": (
                    "Surveillance-adjacent enforcement actions and the perception of "
                    "surveillance pressure reduce foot traffic, suppress business "
                    "activity in affected corridors, and impose compliance costs on "
                    "organizations operating in surveilled areas.  Small businesses, "
                    "informal vendors, and community organizations with thin margins "
                    "are disproportionately affected relative to larger institutions "
                    "that can absorb disruption or relocate operations."
                ),
                "mechanism": "Reduced foot traffic, enforcement uncertainty, compliance costs",
                "affected_population": "Small businesses, informal economy workers, community organizations",
                "measurable_indicator": "Sales volume change, business closure rate, foot traffic data",
            },
            {
                "effect": "deterrence_of_medical_care_seeking",
                "category": "Public Health",
                "description": (
                    "Surveillance operations that collect location and identity data "
                    "deter individuals with outstanding legal concerns — including "
                    "people with immigration status issues, people with outstanding "
                    "warrants for minor violations, and people with stigmatized health "
                    "conditions — from seeking medical care in or near surveilled "
                    "areas.  This is a documented dynamic in communities subject to "
                    "heavy law-enforcement presence and has measurable public-health "
                    "consequences including delayed treatment, increased ED utilization "
                    "for conditions that should have been treated earlier, and "
                    "suppressed uptake of public health programs (testing, vaccination)."
                ),
                "mechanism": "Identity-disclosure risk exceeds perceived benefit of care",
                "affected_population": "Uninsured, undocumented, individuals with minor outstanding warrants",
                "measurable_indicator": "Healthcare utilization rates, treatment delay metrics",
            },
            {
                "effect": "press_freedom_impact",
                "category": "First Amendment / Press Freedom",
                "description": (
                    "Journalists, documentary filmmakers, and photographers who cover "
                    "public demonstrations face identification and tracking by "
                    "surveillance systems that cannot distinguish press from "
                    "participants.  This creates both direct risk (journalists being "
                    "identified and later pressured or subpoenaed) and a chilling "
                    "effect on coverage (journalists choosing not to cover certain "
                    "events or to avoid certain locations).  Reduced press coverage "
                    "of enforcement activity reduces public accountability for "
                    "law-enforcement conduct."
                ),
                "mechanism": "Non-discriminating identification of press alongside participants",
                "affected_population": "Independent journalists, photojournalists, legal observers",
                "measurable_indicator": "Press credentialing requests, coverage gaps, subpoena rates",
            },
        ]

    # ------------------------------------------------------------------
    # Third-order effects catalogue (arms-race dynamics)
    # ------------------------------------------------------------------

    @staticmethod
    def _third_order_effects() -> List[dict]:
        """Arms-race dynamics introduced by each technology layer.

        These are effects that emerge from the interaction between surveillance
        systems and counter-surveillance systems — harms that neither side
        fully intended and that propagate to parties not involved in either.
        """
        return [
            {
                "effect": "surveillance_vendor_ml_adaptation",
                "category": "Arms Race Dynamics",
                "description": (
                    "As GhostTrace is deployed more widely, surveillance-equipment "
                    "vendors gain labeled training examples of GhostTrace traffic.  "
                    "They retrain their WIDS anomaly detectors to recognize the "
                    "statistical signature of Poisson-distributed synthetic frames.  "
                    "Each iteration of counter-detection forces the GhostTrace "
                    "implementation to become more sophisticated, raising the "
                    "technical barrier to effective deployment and accelerating the "
                    "development of more invasive baseline WIDS capabilities that "
                    "are subsequently deployed in contexts having nothing to do with "
                    "protest monitoring."
                ),
                "initiating_layer": "GhostTrace counter-surveillance",
                "propagation_path": "WIDS vendors → general WIDS market → non-protest surveillance contexts",
                "harm_to_uninvolved_parties": "Improved general-purpose device-tracking WIDS",
            },
            {
                "effect": "counter_ghosttrace_wids_raises_costs_for_legitimate_wids",
                "category": "Market Distortion",
                "description": (
                    "WIDS updates developed to counter GhostTrace require denser "
                    "antenna deployments, more compute, and more aggressive per-frame "
                    "analysis.  These costs are passed to all WIDS customers, "
                    "including hospitals, schools, and municipal networks that deploy "
                    "WIDS for legitimate network security purposes and have no "
                    "involvement in surveillance or counter-surveillance.  The "
                    "operational cost of legitimate network security rises as a "
                    "side-effect of an arms race in an unrelated domain."
                ),
                "initiating_layer": "Surveillance vendor WIDS adaptation",
                "propagation_path": "Surveillance WIDS → general WIDS product line → all WIDS customers",
                "harm_to_uninvolved_parties": "Increased cost and complexity of legitimate network security",
            },
            {
                "effect": "bystander_oui_cloning_creates_false_evidence_chains",
                "category": "Collateral Privacy and Legal Harm",
                "description": (
                    "GhostTrace clones OUI prefixes from real bystander devices.  If "
                    "a law-enforcement passive-capture system retains synthetic frames "
                    "alongside real frames, it creates a recorded association between "
                    "a bystander's device OUI and a specific event.  In a subsequent "
                    "legal proceeding, this captured data could be offered as evidence "
                    "of presence.  The bystander has no practical way to demonstrate "
                    "that the frames attributed to their device OUI were synthetic — "
                    "they do not know GhostTrace was operating, they cannot obtain "
                    "the capture data, and the forensic distinction between real and "
                    "synthetic frames at the OUI level is not trivial.  This is a "
                    "structural false-evidence risk created by the counter-surveillance "
                    "system, not by the surveillance system it opposes."
                ),
                "initiating_layer": "GhostTrace OUI sniffing",
                "propagation_path": "Synthetic frames → law-enforcement capture → retained records → legal proceedings",
                "harm_to_uninvolved_parties": "False presence records for uninvolved bystanders",
            },
            {
                "effect": "lora_key_rotation_traffic_creates_new_interception_surface",
                "category": "New Attack Surface",
                "description": (
                    "SENTINEL-NODE's LoRa coordination channel (SX1262 channel 2) "
                    "broadcasts key-rotation payloads to synchronize field agents.  "
                    "This broadcast is encrypted but its existence is detectable "
                    "by a signals-intelligence adversary monitoring the 915 MHz ISM "
                    "band.  The timing of key-rotation broadcasts correlates with "
                    "mode transitions (DEFENDING periods), giving an adversary a "
                    "side-channel to detect when SENTINEL-NODE has identified a "
                    "surveillance indicator.  Additionally, if the Fernet key used "
                    "for broadcast encryption is compromised, an adversary can read "
                    "the full onion address pool and predict future rotation targets, "
                    "allowing deanonymization of the alert channel."
                ),
                "initiating_layer": "SENTINEL-NODE LoRa coordination",
                "propagation_path": "LoRa broadcast → side-channel timing → mode inference → counter-deployment",
                "harm_to_uninvolved_parties": "New signals-intelligence interception surface in ISM band",
            },
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self) -> dict:
        """Produce the full structured policy impact report.

        Returns a dict with the following top-level keys:
        - report_metadata
        - summary
        - second_order_effects
        - third_order_effects
        - ghost_trace_failure_modes
        - salience_fp_events
        - collateral_harms_count
        """
        time_in_mode = self._compute_time_in_mode()
        fp_events = self._false_positive_events()
        fp_rate = self._fp_rate()
        bystander_estimate = self._estimate_bystander_oui_clones()
        transitions = self._transitions()

        # Build FP event summaries
        fp_summaries = []
        for t in fp_events:
            fp_summaries.append({
                "transition_id": str(t.transition_id),
                "timestamp": t.timestamp.isoformat(),
                "from_mode": t.from_mode,
                "to_mode": t.to_mode,
                "salience_at_transition": t.salience_at_transition,
                "fp_reason": getattr(t, "fp_reason", None),
                "failure_flags": getattr(t, "failure_flags", []),
            })

        return {
            "report_metadata": {
                "platform": "SENTINEL-NODE synthetic policy demonstration",
                "generated_at": _now_utc().isoformat(),
                "disclaimer": (
                    "All data is fictional and produced by simulation.  "
                    "This report is intended for policymaker education only."
                ),
            },
            "summary": {
                "time_in_listening_seconds": round(time_in_mode["LISTENING"], 2),
                "time_in_defending_seconds": round(time_in_mode["DEFENDING"], 2),
                "time_in_listening_human": _fmt_duration(time_in_mode["LISTENING"]),
                "time_in_defending_human": _fmt_duration(time_in_mode["DEFENDING"]),
                "total_transitions": len(transitions),
                "false_positive_transitions": len(fp_events),
                "false_positive_rate": round(fp_rate, 4),
                "total_alerts_dispatched": sum(
                    1 for a in self._alert_log if not a.dispatch_error
                ),
                "total_dispatch_errors": sum(
                    1 for a in self._alert_log if a.dispatch_error
                ),
                "total_snapshots": len(self._snapshots()),
            },
            "second_order_effects": self._second_order_effects(),
            "third_order_effects": self._third_order_effects(),
            "ghost_trace_failure_modes": self._gt.failure_modes(),
            "salience_fp_events": fp_summaries,
            "collateral_harms_count": {
                "estimated_bystander_oui_clones": bystander_estimate,
                "estimation_method": (
                    "dispatched_alerts × virtual_device_count (upper bound; "
                    "each GhostTrace burst during a DEFENDING period clones "
                    "at most one OUI per virtual device)"
                ),
                "note": (
                    "This is a minimum estimate.  A real deployment over a longer "
                    "event would accumulate OUI clones proportional to burst "
                    "duration × per-device frame rate × checkpoint retention rate."
                ),
            },
        }

    def to_markdown(self) -> str:
        """Render the policy impact report as a markdown document.

        The output is formatted for a policy brief audience: section headers,
        plain-language descriptions, and explicit callouts for the most
        consequential harms.  Technical metrics are presented with context.

        Returns
        -------
        str
            Markdown-formatted report text.
        """
        data = self.generate()
        summary = data["summary"]
        meta = data["report_metadata"]
        bystander = data["collateral_harms_count"]

        lines: List[str] = []

        # Header
        lines += [
            "# SENTINEL-NODE Policy Impact Report",
            "",
            f"**Generated**: {meta['generated_at']}  ",
            f"**Platform**: {meta['platform']}  ",
            f"**Disclaimer**: {meta['disclaimer']}",
            "",
            "---",
            "",
        ]

        # Executive summary
        lines += [
            "## Executive Summary",
            "",
            "This report aggregates outputs from a SENTINEL-NODE simulation run.  "
            "It is structured around three layers of analysis:",
            "",
            "1. **Operational summary** — how the system behaved during the simulation",
            "2. **Second-order effects** — downstream harms from the surveillance "
            "infrastructure that motivated SENTINEL-NODE deployment",
            "3. **Third-order effects** — arms-race dynamics that emerge from the "
            "interaction between surveillance and counter-surveillance systems",
            "",
        ]

        # Operational summary
        lines += [
            "## Operational Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Time in LISTENING mode | {summary['time_in_listening_human']} |",
            f"| Time in DEFENDING mode | {summary['time_in_defending_human']} |",
            f"| Total mode transitions | {summary['total_transitions']} |",
            f"| False-positive transitions | {summary['false_positive_transitions']} |",
            f"| False-positive rate | {summary['false_positive_rate']:.1%} |",
            f"| Alerts dispatched | {summary['total_alerts_dispatched']} |",
            f"| Dispatch errors | {summary['total_dispatch_errors']} |",
            f"| Total salience snapshots | {summary['total_snapshots']} |",
            "",
        ]

        # False-positive events
        fp_events = data["salience_fp_events"]
        if fp_events:
            lines += [
                "### False-Positive Transition Detail",
                "",
                "The following mode transitions were retrospectively assessed as "
                "false positives.  Each represents a period during which the "
                "system activated counter-measures in response to a signal that "
                "was not actually a surveillance indicator.",
                "",
            ]
            for i, fp in enumerate(fp_events, 1):
                lines += [
                    f"**FP-{i}** `{fp['transition_id']}`  ",
                    f"Timestamp: {fp['timestamp']}  ",
                    f"Transition: {fp['from_mode']} → {fp['to_mode']}  ",
                    f"Salience at transition: {fp['salience_at_transition']:.4f}  ",
                    f"Reason: {fp['fp_reason'] or 'not recorded'}  ",
                    "",
                ]
        else:
            lines += [
                "### False-Positive Transition Detail",
                "",
                "No transitions were retrospectively assessed as false positives "
                "in this simulation run.",
                "",
            ]

        # Collateral harm estimate
        lines += [
            "## Collateral Harm Estimate (GhostTrace OUI Cloning)",
            "",
            "> **This section describes harm caused by the counter-surveillance "
            "system, not by the surveillance system it opposes.**",
            "",
            f"**Estimated bystander OUI clone events**: "
            f"{bystander['estimated_bystander_oui_clones']}",
            "",
            f"_Estimation method_: {bystander['estimation_method']}",
            "",
            bystander["note"],
            "",
            "When GhostTrace initializes, it passively sniffs 802.11 probe "
            "requests from real devices in the vicinity.  It then uses those "
            "device OUI prefixes to generate synthetic frames.  This means "
            "uninvolved bystanders — passersby, nearby residents, workers — "
            "have their device identities cloned and asserted at times and "
            "locations they did not choose.  If law-enforcement capture systems "
            "retain these frames, false evidence chains may be created for "
            "people who were simply nearby.",
            "",
        ]

        # Second-order effects
        lines += [
            "## Second-Order Effects of Surveillance Infrastructure",
            "",
            "These are harms caused by the surveillance systems that motivated "
            "SENTINEL-NODE deployment — not harms caused by SENTINEL-NODE itself.",
            "",
        ]
        for effect in data["second_order_effects"]:
            lines += [
                f"### {effect['effect'].replace('_', ' ').title()}",
                "",
                f"**Category**: {effect['category']}  ",
                f"**Mechanism**: {effect['mechanism']}  ",
                f"**Affected population**: {effect['affected_population']}  ",
                f"**Measurable indicator**: {effect['measurable_indicator']}",
                "",
                effect["description"],
                "",
            ]

        # Third-order effects
        lines += [
            "## Third-Order Effects — Arms Race Dynamics",
            "",
            "These are effects that emerge from the interaction between "
            "surveillance and counter-surveillance systems, propagating to "
            "parties not involved in either.",
            "",
        ]
        for effect in data["third_order_effects"]:
            lines += [
                f"### {effect['effect'].replace('_', ' ').title()}",
                "",
                f"**Category**: {effect['category']}  ",
                f"**Initiating layer**: {effect['initiating_layer']}  ",
                f"**Propagation path**: {effect['propagation_path']}  ",
                f"**Harm to uninvolved parties**: {effect['harm_to_uninvolved_parties']}",
                "",
                effect["description"],
                "",
            ]

        # GhostTrace failure modes
        lines += [
            "## GhostTrace Failure Mode Analysis",
            "",
            "The following failure modes were identified in the GhostTrace "
            "simulation.  Each represents a condition under which the deception "
            "layer fails, either by being detected or by causing unintended harm.",
            "",
        ]
        for fm in data["ghost_trace_failure_modes"]:
            severity_tag = f"**[{fm['severity']}]**"
            collateral_tag = " _(second-order harm)_" if fm["second_order_harm"] else ""
            lines += [
                f"### {fm['id']}{collateral_tag}",
                "",
                f"{severity_tag} {fm['name']}  ",
                f"**Detection vector**: {fm['detection_vector']}",
                "",
            ]
            # Wrap long description paragraphs for readability
            for para in fm["description"].split("\n\n"):
                lines.append(para.strip())
                lines.append("")
            lines += [
                f"_Mitigation_: {fm['mitigation']}",
                "",
            ]

        # Footer
        lines += [
            "---",
            "",
            "_This document was generated by SENTINEL-NODE, a synthetic policy "
            "demonstration platform.  No real surveillance systems, network "
            "traffic, or radio transmissions were involved.  All data is "
            "fictional and produced for policymaker education only._",
        ]

        return "\n".join(lines)
