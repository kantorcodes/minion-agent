from .base import Callback
from .context import Context
from .hol_guard import HolGuardBlocked, HolGuardCallback
from .span_cost import AddCostInfo
from .span_print import ConsolePrintSpan

__all__ = [
    "Callback",
    "ConsolePrintSpan",
    "Context",
    "HolGuardBlocked",
    "HolGuardCallback",
]


def get_default_callbacks() -> list[Callback]:
    """Return instances of the default callbacks used in minion-agent.

    This function is called internally when the user doesn't provide a
    value for [`AgentConfig.callbacks`][minion_agent.config.AgentConfig.callbacks].

    Returns:
        A list of instances containing:

            - [`AddCostInfo`][minion_agent.callbacks.span_cost.AddCostInfo]
            - [`ConsolePrintSpan`][minion_agent.callbacks.span_print.ConsolePrintSpan]

    """
    return [AddCostInfo(), ConsolePrintSpan()]
