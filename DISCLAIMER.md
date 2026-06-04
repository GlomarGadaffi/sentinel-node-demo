# disclaimer

This document establishes what SENTINEL-NODE is, what it is not, and the specific policy purpose it serves.

---

## What SENTINEL-NODE is

A synthetic software demonstration of a class of community counter-surveillance systems that emerge under conditions of intensive, broad-spectrum state surveillance of civilian populations. It is built to make the following legible to policymakers, researchers, and civil society organizations:

1. **What these systems look like** — their architecture, component costs, and operational logic
2. **The conditions that produce them** — the asymmetric surveillance pressure that makes their development rational
3. **Their failure modes** — where and how they break, and the collateral harms those failures produce
4. **Second and third order effects** — the arms race dynamics, bystander harms, and policy consequences that follow from both the surveillance being responded to and the counter-systems it generates

The entire codebase runs on synthetic data. No actual RF signals are captured, processed, or transmitted. No real agency frequencies, real ICAO codes, real mesh network identities, or real individuals appear anywhere in the demonstration.

---

## What SENTINEL-NODE is not

It is not a deployable field system. It is not a guide to building one. It is not firmware. It is not hardware design. The physical implementation layer — the ESP32-P4, the RTL-SDR receivers, the SX1262 transceivers, the PCB stack, the PoE integration, the Buildroot environment — is not published here and will not be. What is here is the software logic layer, running against synthetic inputs, producing analytical outputs and policy reports.

The GhostTrace module models the mathematics of a deception engine and documents its failure modes. It does not transmit. The ShroudSpeak module demonstrates cryptographic packet structure. It does not route through Tor. The pocket-dial reference is to an external project. None of these components are connected to hardware.

---

## The policy argument this demonstration makes

Intensive, broad-spectrum civilian surveillance — particularly when applied non-selectively across protected communities — produces rational, predictable, and increasingly sophisticated defensive responses. The $95 bill of materials in the accompanying documentation is not a threat claim. It is a cost signal to policymakers: the marginal cost of building this class of system has fallen below the threshold at which it can be suppressed by equipment scarcity.

The demonstration makes three specific policy-relevant claims:

**Claim 1: Surveillance pressure is generative.** Systems like SENTINEL-NODE are not the cause of community distrust of state surveillance. They are its product. The conditions documented in Operation Metro Surge — non-targeted stops at 43.9% frequency, enforcement at sensitive locations, warrantless entry — are the input. The emergence of this architecture is a predictable output.

**Claim 2: Counter-systems cause their own harms.** The GhostTrace deception engine, even when functioning correctly, clones the wireless identities of uninvolved bystanders to construct its anonymity set. The surveillance system being countered harms the community. The counter-system harms the bystanders. Neither harm is visible in the primary policy debate. This demonstration makes both visible.

**Claim 3: Arms race dynamics are asymmetric and costly.** The salience engine's false positive rate under dense civilian conditions (concerts, protests, public gatherings) means the system will trigger Defending Mode during events that have nothing to do with tactical enforcement. Each false positive causes a GhostTrace burst that degrades the quality of location data for everyone in the area. Each degraded location data point costs real money for vendors who sell that data, real accuracy for systems that rely on it, and real investigative value for the lawful uses of the surveillance infrastructure. These costs are diffuse, invisible, and almost impossible to attribute. This demonstration traces them.

---

## The failure modes this demonstration documents

The following failure modes are implemented and measurable in the demonstration:

- **FALSE_POSITIVE_DENSE_CIVILIAN** — A large public gathering (protest, concert) triggers DEFENDING Mode incorrectly. GhostTrace activates. Bystander OUIs are cloned.
- **FALSE_POSITIVE_AVIATION_COMMERCIAL** — A departing commercial flight spikes the aviation proximity term. The system defends against a Delta 737.
- **FALSE_NEGATIVE_SUPPRESSED_MESH** — Mesh jamming drops the M_d term to zero during an actual operation. The system fails to detect a real threat.
- **WIDS_SEQUENCE_DETECTION** — GhostTrace's FSM-tracked sequence numbers are detectable by sufficiently sophisticated WIDS systems that track per-MAC behavior across channels.
- **SURVEILLANCE_ML_ADAPTATION** — The Poisson timing distribution of GhostTrace is a detectable signature. A trained classifier identifies the counter-system rather than the targets.
- **COLLATERAL_PRIVACY_HARM** — The most important failure mode. The OUI spoofing system clones real bystander device identities and asserts their presence at locations they were not. This creates false evidence records in surveillance databases that the bystanders cannot see, cannot challenge, and cannot correct.

---

## Prohibited uses

This codebase may not be used to build an operational system. It may not be used to process real RF data. It may not be used to generate real decoy transmissions. It may not be used to track, monitor, interfere with, or evade the detection of any specific person, agency, or operation.

The synthetic envelope is not a temporary convenience. It is the permanent and load-bearing operating constraint of this project.

---

## Contact

The methodology, its policy implications, and principled disagreement with any claim in this document are welcome through the project's public contact surface. Requests for hardware specifications, firmware, operational configurations, or real-frequency databases will be ignored.
