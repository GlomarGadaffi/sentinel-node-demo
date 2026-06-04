"""
defend/ — SENTINEL-NODE defend layer.

SENTINEL-NODE synthetic policy demonstration platform.
All data is fictional and used solely to demonstrate system behavior
under simulated enforcement pressure for policymaker education.

This package contains three modules:

shroud_speak
    Alert packaging and Ed25519 signing.  Demonstrates the cryptographic
    boundary and packet structure of shroud-speak alerts.  In deployment
    these alerts would route through an arti-client Tor tunnel.  No actual
    network calls are made here.

ghost_trace
    GhostTrace deception engine simulation.  Models the synthetic 802.11
    frame sequences that an ESP32-C6 running GhostTrace firmware would
    generate, and provides analytical outputs for failure-mode and
    second-order-effect analysis.  No radio hardware is accessed and no
    frames are transmitted.

policy_report
    Policy impact report generator.  Aggregates state-machine telemetry,
    GhostTrace simulation outputs, and alert logs into a structured report
    for policymaker audiences.  Renders as a structured dict or markdown.
"""

from defend.shroud_speak import OnionAddressRotator, ShroudSpeakAlert
from defend.ghost_trace import GhostTraceSimulator
from defend.policy_report import PolicyReportGenerator

__all__ = [
    "ShroudSpeakAlert",
    "OnionAddressRotator",
    "GhostTraceSimulator",
    "PolicyReportGenerator",
]
