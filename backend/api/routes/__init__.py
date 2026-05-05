"""API route modules.

Each module exports a ``router: APIRouter`` that ``server.py`` includes
into the main `/api`-prefixed router. Route handlers receive their
dependencies via FastAPI's ``Depends()`` so this package never imports
from ``server`` directly — it only depends on ``api.deps``.
"""
