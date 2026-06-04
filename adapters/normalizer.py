"""
SENTINEL-NODE ingestion normalizer.

Routes a named source to its synthetic adapter and returns a list of
ThreatIndicator objects ready for the salience engine. Mirrors the
MirkwoodNormalizer pattern from the Mirkwood reference architecture.

Registered sources
------------------
"EDACS"       -> EDACSSyntheticAdapter.generate_scenario(scenario)
"ADS_B"       -> ADSBSyntheticAdapter.generate_scenario(scenario, node_lat, node_lon)
"MESHTASTIC"  -> MeshtasticPassiveAdapter.generate_scenario(scenario, node_lat, node_lon)

All adapters return SYNTHETIC data — see individual adapter modules for
the threat model and policy-demonstration context.
"""

from typing import Any, List

from adapters.base import ThreatIndicator
from adapters.edacs import EDACSSyntheticAdapter
from adapters.adsb import ADSBSyntheticAdapter
from adapters.meshtastic_passive import MeshtasticPassiveAdapter


class SentinelNormalizer:
    """
    Top-level ingestion router for SENTINEL-NODE.

    Usage
    -----
    normalizer = SentinelNormalizer()

    # EDACS — no lat/lon required
    indicators = normalizer.generate("EDACS", "tactical_surge")

    # ADS-B — node position required
    indicators = normalizer.generate(
        "ADS_B", "surveillance_pattern",
        node_lat=37.7749, node_lon=-122.4194
    )

    # Meshtastic — node position required
    indicators = normalizer.generate(
        "MESHTASTIC", "active_spotters",
        node_lat=37.7749, node_lon=-122.4194
    )
    """

    def __init__(self) -> None:
        self._adapters = {
            "EDACS":       EDACSSyntheticAdapter(),
            "ADS_B":       ADSBSyntheticAdapter(),
            "MESHTASTIC":  MeshtasticPassiveAdapter(),
        }

    def generate(
        self,
        source: str,
        scenario: str,
        **kwargs: Any,
    ) -> List[ThreatIndicator]:
        """
        Generate synthetic ThreatIndicators for the given source and scenario.

        Parameters
        ----------
        source : str
            Registered source name. One of: "EDACS", "ADS_B", "MESHTASTIC".
        scenario : str
            Scenario name passed to the adapter. See each adapter's docstring
            for supported values.
        **kwargs
            Additional keyword arguments forwarded to the adapter. Required
            kwargs by source:
              ADS_B       — node_lat: float, node_lon: float
              MESHTASTIC  — node_lat: float, node_lon: float
              EDACS       — (none beyond scenario)

        Returns
        -------
        List[ThreatIndicator]
            Zero or more normalized threat indicators ready for the salience
            engine. An empty list is a valid result (e.g., "no_aircraft").

        Raises
        ------
        ValueError
            If source is not registered or the scenario is unknown to the
            selected adapter.
        KeyError
            If a required kwarg (node_lat, node_lon) is missing for an
            adapter that needs it.
        """
        if source not in self._adapters:
            registered = ", ".join(f'"{k}"' for k in self._adapters)
            raise ValueError(
                f"No adapter registered for source '{source}'. "
                f"Registered sources: {registered}."
            )

        adapter = self._adapters[source]

        if source == "EDACS":
            return adapter.generate_scenario(scenario)

        if source in ("ADS_B", "MESHTASTIC"):
            node_lat = kwargs["node_lat"]
            node_lon = kwargs["node_lon"]
            return adapter.generate_scenario(scenario, node_lat, node_lon)

        # Unreachable given the registered set above, but guard for future sources
        raise ValueError(f"Adapter dispatch logic not implemented for source '{source}'.")

    @property
    def registered_sources(self) -> List[str]:
        """Return the list of registered source names in insertion order."""
        return list(self._adapters.keys())
