# src/logger.py
# Centralized logging utility.
# Provides functions to log events, errors, and status updates, crucial for debugging and monitoring the long-running analyzer process.

# src/logger.py
from loguru import logger

def setup_logging(level: str = "INFO"):
    logger.remove()
    logger.add(lambda msg: print(msg, end=""), level=level)
    logger.info("Logger initialized at level {}", level)
    return logger
