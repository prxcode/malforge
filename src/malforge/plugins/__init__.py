import logging
from importlib.metadata import entry_points

from malforge.plugins.base import MalforgePlugin

__all__ = ["PLUGIN_GROUP", "MalforgePlugin", "load_plugins"]

logger = logging.getLogger(__name__)

PLUGIN_GROUP = "malforge.plugins"


def load_plugins() -> list[MalforgePlugin]:
    """Instantiate every plugin registered under the ``malforge.plugins`` entry point group."""
    plugins: list[MalforgePlugin] = []
    for ep in entry_points(group=PLUGIN_GROUP):
        try:
            plugin_class = ep.load()
        except Exception:
            logger.exception("Failed to import plugin %s", ep.name)
            continue

        if not (isinstance(plugin_class, type) and issubclass(plugin_class, MalforgePlugin)):
            logger.warning("Plugin %s does not subclass MalforgePlugin; skipping", ep.name)
            continue

        try:
            plugins.append(plugin_class())
        except Exception:
            logger.exception("Failed to initialise plugin %s", ep.name)
    return plugins
