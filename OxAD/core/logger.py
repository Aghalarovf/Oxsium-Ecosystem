from __future__ import annotations

import logging


def setup_logger(verbose: bool = False) -> logging.Logger:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )
    logger = logging.getLogger("oxad")
    logger.setLevel(level)
    return logger
