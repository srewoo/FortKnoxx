"""CLI entry point — exposes `fortknoxx-mcp` as a console script."""

from __future__ import annotations

import asyncio
import logging

from .config import load_settings
from .server import run_stdio


def main() -> None:
    settings = load_settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    asyncio.run(run_stdio())


if __name__ == "__main__":
    main()
