"""fleet-sentinel: corroborated health verdicts for remote Hermes agent hosts.

Modules:

* :mod:`.config`   settings defaults, merge and validation (never raises)
* :mod:`.probe`    probe ladder: tailscale, TCP, one ssh round trip; pure parsers
* :mod:`.verdict`  corroboration rules -> up / deaf / down_physical / degraded / unknown
* :mod:`.store`    sqlite history and alert anchors
* :mod:`.escalate` escalation ladder and plain-text alert rendering
* :mod:`.recover`  recovery verbs (dry run by default)
* :mod:`.runtime`  orchestration shared by tools, CLI and slash command
* :mod:`.tools`    tool schemas and JSON handlers
* :mod:`.cli`      ``hermes fleet-sentinel`` argparse tree
"""

from __future__ import annotations

__version__ = "1.0.0"
PLUGIN_NAME = "fleet-sentinel"

__all__ = ["__version__", "PLUGIN_NAME"]
