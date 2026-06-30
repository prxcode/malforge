

import logging
from importlib.metadata import entry_points

from malforge.plugins.base import MalforgePlugin

logger = logging.getLogger(__name__)

PLUGIN_GROUP = "malforge.plugins"


def load_plugins() -> list[MalforgePlugin]:
    """Discover and load all registered malforge plugins."""
    plugins: list[MalforgePlugin] = []

    discovered = entry_points()
    # Python 3.12+ returns a SelectableGroups, 3.9+ supports .select()
    if hasattr(discovered, "select"):
        group = discovered.select(group=PLUGIN_GROUP)
    else:
        group = discovered.get(PLUGIN_GROUP, [])

    for ep in group:
        try:
            plugin_class = ep.load()
            plugin = plugin_class()
            if not isinstance(plugin, MalforgePlugin):
                logger.warning(
                    "Plugin %s does not extend MalforgePlugin, skipping", ep.name
                )
                continue
            plugins.append(plugin)
            logger.info("Loaded plugin: %s v%s", plugin.name, plugin.version)
        except Exception as e:
            logger.error("Failed to load plugin %s: %s", ep.name, e)

    return plugins
