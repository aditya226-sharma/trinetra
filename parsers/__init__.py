"""Parsers package — plug-and-play per-source parsers (PS26156-e).

Importing this package registers every built-in parser decorators. The
registry pattern is the whole point: adding a brand-new log source type
is a *single decorated function* — nothing downstream changes.

Example (PUT THIS IN parsers/<name>.py):

    from parsers.registry import register_parser

    @register_parser("mylog")
    def parse_mylog(raw, source, client_id, host_hint=""):
        ...  # return a dict of UES-normalized fields, or None
"""

from parsers import (  # noqa: F401  -- imports run the @register_parser decorators
    cef,
    csv_log,
    json_log,
    netflow,
    syslog,
    windows,
)