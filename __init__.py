"""fleet-sentinel Hermes plugin entry point. ``register(ctx)`` only; all logic lives in ``sentinel/``.

Imports are deferred into ``register`` so importing this file (e.g. by a test collector) has no
side effects and needs no package context.
"""

from __future__ import annotations

from typing import Any

_SETTING_KEYS = ("hosts", "thresholds", "auto_heal")


def register(ctx: Any) -> None:
    from .sentinel import cli
    from .sentinel.approval import approval_hook
    from .sentinel.runtime import Sentinel
    from .sentinel.tools import EMOJI, SCHEMAS, TOOLSET, make_handlers

    def settings() -> dict[str, Any]:
        raw = {key: ctx.get_config(key) for key in _SETTING_KEYS}
        return {k: v for k, v in raw.items() if v is not None}

    # A model-set flag is not consent: any fleet_recover that would act is
    # escalated to the human-approval gate (fails closed when unattended).
    ctx.register_hook("pre_tool_call", approval_hook)

    sentinel = Sentinel(settings)
    handlers = make_handlers(sentinel)
    for name, schema in SCHEMAS.items():
        ctx.register_tool(name=name, toolset=TOOLSET, schema=schema, handler=handlers[name],
                          description=schema["description"], emoji=EMOJI)

    def handle_cli(args: Any) -> int:
        runner = Sentinel(settings)
        try:
            return cli.run(runner, args, get=ctx.get_config, put=ctx.set_config)
        finally:
            runner.close()

    ctx.register_cli_command(
        name="fleet-sentinel",
        help="Corroborated health of remote Hermes agent hosts",
        setup_fn=cli.setup_parser,
        handler_fn=handle_cli,
        description="Probe fleet hosts (tailnet, TCP, ssh), page on sustained outages, recover gateways.",
    )

    def slash(raw_args: str = "") -> str:
        if raw_args.strip().lower() in ("live", "probe", "now"):
            return sentinel.live_text()
        return sentinel.cached_text()

    ctx.register_command("sentinel", handler=slash,
                         description="Fleet health (cached; `/sentinel live` probes now)",
                         args_hint="[live]")
