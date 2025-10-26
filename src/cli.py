# src/cli.py
# The command-line entrypoint for running the analyzer. Parses arguments like --mode capture or --mode analyze and dispatches control to the relevant modules.
import argparse
from logger import setup_logging
from config_loader import load_config

def main():
    parser = argparse.ArgumentParser(prog="net-analyzer")
    parser.add_argument("--config", "-c", default="config/config.yaml")
    parser.add_argument("--mode", choices=["capture", "analyze", "all", "streamlit"], default="all")
    args = parser.parse_args()
    logger = setup_logging("INFO")
    cfg = load_config(args.config)
    logger.info("Loaded configuration")
    # TODO: dispatch to modules
    if args.mode in ("capture", "all"):
        logger.info("Starting capture module (placeholder)")
    if args.mode in ("analyze", "all"):
        logger.info("Starting analysis module (placeholder)")

if __name__ == "__main__":
    main()
