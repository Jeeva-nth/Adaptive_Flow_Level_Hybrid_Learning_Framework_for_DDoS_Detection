"""
Module 2: Traffic Capture — Main module for real-time DDoS attack detection.
Captures live network packets using PyShark and orchestrates the detection pipeline.
"""
import logging
import sys
from typing import Optional

import pyshark

from app.feature_extraction import calculate_flow_features
from app.model_prediction import predict_attack
from app.logging_monitor import setup_logging
from config.settings import Config


# Use centralised logging
setup_logging(service_name='detection')
logger = logging.getLogger(__name__)


def packet_callback(packet) -> None:
    """
    Callback called for each captured packet.

    Args:
        packet: Packet captured by pyshark
    """
    try:
        # Validate it's a TCP/IP packet (both layers required)
        if 'IP' not in packet or 'TCP' not in packet:
            logger.debug("Non-TCP/IP packet ignored")
            return

        logger.debug(
            f"TCP packet captured: {packet.ip.src}:{packet.tcp.srcport} -> "
            f"{packet.ip.dst}:{packet.tcp.dstport}"
        )

        # Extract features from packet
        features = calculate_flow_features(packet)

        if features:
            logger.debug(f"Features extracted: {len(features)} features")
            predict_attack(features)
        else:
            # None is returned either because the flow hasn't accumulated
            # enough packets yet (normal, expected) or because of a parse
            # error (logged inside calculate_flow_features).  Debug-level
            # only so the log isn't flooded during normal operation.
            logger.debug("Features not ready yet (flow accumulating packets)")

    except KeyError as e:
        logger.warning(f"Incomplete packet (missing field): {e}")
    except Exception as e:
        logger.error(f"Error processing packet: {e}", exc_info=True)


def start_detection(
    interface: Optional[str] = None,
    bpf_filter: Optional[str] = None
) -> None:
    """
    Start packet capture and detection.

    Args:
        interface: Network interface for capture (default: Config.NETWORK_INTERFACE)
        bpf_filter: BPF filter for capture (default: Config.BPF_FILTER)
    """
    interface = interface or Config.NETWORK_INTERFACE
    bpf_filter = bpf_filter or Config.BPF_FILTER

    logger.info(f"Starting packet capture on interface '{interface}'")
    logger.info(f"BPF filter: {bpf_filter}")

    try:
        # Validate model is available before starting capture
        from app.model_prediction import get_predictor
        get_predictor()
        logger.info("Detection system initialized successfully")

        # Start capture — apply_on_packets is synchronous; no event loop needed
        capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)

        logger.info("Capture started. Waiting for packets...")
        logger.info("Press Ctrl+C to stop")

        capture.apply_on_packets(packet_callback)

    except KeyboardInterrupt:
        logger.info("Capture interrupted by user")
    except PermissionError:
        # Fix #1/#2: PermissionError must come BEFORE the bare Exception clause
        # so it is not swallowed by the generic handler below.
        logger.error(
            "Permission denied. Run with sudo/Administrator to capture packets:\n"
            "  sudo python3 -m app.detection"
        )
        sys.exit(1)
    except Exception as e:
        err_str = str(e).lower()
        type_name = type(e).__name__
        if 'tshark' in type_name.lower() or 'tshark' in err_str:
            logger.error(
                "TShark not found. Please install Wireshark/TShark:\n"
                "  Linux:   sudo apt-get install tshark\n"
                "  macOS:   brew install wireshark\n"
                "  Windows: Install Wireshark from https://www.wireshark.org/"
            )
            sys.exit(1)
        logger.error(f"Error starting capture: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logger.info("Detection system stopped")


if __name__ == '__main__':
    start_detection()
