"""
Experimental Setup: Flask server for DDoS attack target simulation.
A lightweight web server used as a target system to generate real-time traffic.
"""
from flask import Flask, jsonify, Response
import logging
import sys
from typing import Tuple

from config.settings import Config
from app.logging_monitor import setup_logging

# Use centralised logging
setup_logging(service_name='server')
logger = logging.getLogger(__name__)

# Create Flask instance
app = Flask(__name__)


@app.route('/', methods=['GET'])
def index() -> Response:
    """Main server endpoint."""
    logger.info("Request received at '/' route")
    return jsonify({"status": "online", "message": "Server is running!"})


@app.route('/health', methods=['GET'])
def health() -> Response:
    """Health check endpoint."""
    return jsonify({"status": "healthy", "service": "ddos-detection-simulator"})


@app.errorhandler(404)
def not_found(error) -> Tuple[Response, int]:
    """Handler for routes not found."""
    logger.warning(f"Route not found: {error}")
    return jsonify({"error": "Route not found"}), 404


@app.errorhandler(500)
def internal_error(error) -> Tuple[Response, int]:
    """Handler for internal errors."""
    logger.error(f"Internal error: {error}", exc_info=True)
    return jsonify({"error": "Internal server error"}), 500


def main() -> None:
    """Main function to start the server."""
    try:
        logger.info(f"Starting Flask server on port {Config.FLASK_PORT}")
        logger.info(f"Host: {Config.FLASK_HOST}")
        logger.info(f"Debug: {Config.DEBUG}")
        
        app.run(
            host=Config.FLASK_HOST,
            port=Config.FLASK_PORT,
            debug=Config.DEBUG
        )
    except Exception as e:
        logger.error(f"Error starting server: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("Flask server stopped")


if __name__ == '__main__':
    main()
