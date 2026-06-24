# sentinel-node-demo

SENTINEL-NODE: synthetic demonstration of surveillance / counter-surveillance 2nd and 3rd order effects. models multi-source RF signal fusion (trunking, aviation, mesh networks) against adaptive defensive postures to illustrate feedback loops, strategic vulnerabilities, and information asymmetries.

## architecture

**signal adapters** normalize inputs from heterogeneous sources:
- EDACS trunking (terrestrial police/fire/EMS)
- ADS-B (aviation, transponder positions)
- Meshtastic (passive mesh network monitoring)

**salience engine** computes composite threat score S(t):
- `trunking_term`: weighted control-channel activity density
- `aviation_term`: airframe proximity and density (km radius)
- `mesh_term`: active relay detections and message volume

**mode machine** maintains state:
- **LISTENING** (default): passive, low-overhead monitoring
- **DEFENDING** (reactive): activates countermeasures when S(t) > threshold

**transitions**: reversible, timestamped, with failure-flag forensics for post-hoc analysis

## data model

```
ThreatIndicator
  ├─ event_id, timestamp, channel (EDACS|ADS_B|MESHTASTIC)
  ├─ lat/lon (geospatial anchor)
  ├─ primary_id (talkgroup / aircraft / node)
  ├─ secondary_ids (participants, relays)
  └─ metadata (frequency, altitude, encryption state, etc.)

SalienceSnapshot
  ├─ score, component terms (trunking, aviation, mesh)
  ├─ mode (LISTENING | DEFENDING)
  └─ trigger_reason (if transition occurred)

ModeTransition
  ├─ from_mode, to_mode, trigger_snapshot_id
  ├─ retrospective_fp (false positive flag for model learning)
  └─ failure_flags (defensive action failures, if any)
```

## use cases

**accountability research**: demonstrate how passive RF reconnaissance can correlate with physical security postures; illustrate opacity/illegibility trade-offs.

**policy analysis**: 2nd-order effects (radio silence ≈ operational shutdown; encryption ≈ signal isolation ≈ communication latency) for emergency response design.

**defensive modeling**: agent-based simulation of adaptive response strategies under incomplete information.

## notes

synthetic data only. designed to be reproducible and debuggable for policy stakeholders.
