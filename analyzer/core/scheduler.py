from apscheduler.schedulers.background import BackgroundScheduler
from analyzer.core.packet_collector import capture_traffic, analyze_packets
from analyzer.core.influx_client import write_data
from loguru import logger

scheduler = BackgroundScheduler()

def collect_and_store():
    try:
        packets = capture_traffic(duration=10)  # capture for 10s
        metrics = analyze_packets(packets)

        if metrics:
            write_data("network_metrics", metrics)
            logger.info(f"✅ Metrics captured automatically: {metrics['total_packets']} packets")
        else:
            logger.warning("⚠️ No packets captured in automated cycle.")

    except Exception as e:
        logger.error(f"Error during automated capture: {e}")

def start_scheduler(interval_minutes=1):
    scheduler.add_job(collect_and_store, 'interval', minutes=interval_minutes)
    scheduler.start()
    logger.info(f"⏰ Scheduler started (every {interval_minutes} minutes)")
