"""
Module 6: Centralized Logging and Monitoring Module
Provides unified logging setup, structured event recording, and an in-memory
ring buffer for real-time dashboard consumption.

Cross-process sharing
---------------------
When the detection engine and the dashboard run in separate processes (e.g.
Docker containers) the in-memory EventBuffer is not shared.  This module
bridges that gap with an optional Redis backend.

Redis is optional.  Set REDIS_HOST / REDIS_PORT / REDIS_PASSWORD environment
variables (or leave them at their defaults) to enable it.
"""
import logging
import sys
import json
import threading
from collections import deque
from datetime import datetime
from typing import Dict, List, Optional

from config.settings import Config

try:
    import redis as _redis_lib
    _REDIS_AVAILABLE = True
except ImportError:
    _REDIS_AVAILABLE = False


# ── DetectionEvent ─────────────────────────────────────────────────────────

class DetectionEvent:
    """Represents a single detection event for structured logging."""

    __slots__ = ('timestamp', 'event_type', 'confidence', 'threshold',
                 'rf_confidence', 'svm_confidence', 'source_ip',
                 'destination_ip', 'message')

    def __init__(
        self,
        event_type: str,
        confidence: float = 0.0,
        threshold: float = 0.0,
        rf_confidence: float = 0.0,
        svm_confidence: float = 0.0,
        source_ip: str = '',
        destination_ip: str = '',
        message: str = ''
    ):
        self.timestamp = datetime.now().isoformat()
        self.event_type = event_type
        self.confidence = confidence
        self.threshold = threshold
        self.rf_confidence = rf_confidence
        self.svm_confidence = svm_confidence
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.message = message

    def to_dict(self) -> Dict:
        return {
            'timestamp': self.timestamp,
            'event_type': self.event_type,
            'confidence': self.confidence,
            'threshold': self.threshold,
            'rf_confidence': self.rf_confidence,
            'svm_confidence': self.svm_confidence,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'message': self.message,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'DetectionEvent':
        evt = cls(
            event_type=data.get('event_type', 'info'),
            confidence=data.get('confidence', 0.0),
            threshold=data.get('threshold', 0.0),
            rf_confidence=data.get('rf_confidence', 0.0),
            svm_confidence=data.get('svm_confidence', 0.0),
            source_ip=data.get('source_ip', ''),
            destination_ip=data.get('destination_ip', ''),
            message=data.get('message', ''),
        )
        if 'timestamp' in data:
            evt.timestamp = data['timestamp']
        return evt


# ── Redis bridge ───────────────────────────────────────────────────────────

_REDIS_KEY_EVENTS = 'ddos:events'
_REDIS_CHANNEL    = 'ddos:events'
_REDIS_KEY_RATES  = 'ddos:rates'


class RedisBridge:
    """Optional Redis bridge for cross-process event sharing."""

    def __init__(self):
        self._client: Optional[object] = None
        self._lock = threading.Lock()
        self._connect()

    def _connect(self) -> None:
        if not _REDIS_AVAILABLE:
            return
        try:
            kwargs: Dict = {
                'host': Config.REDIS_HOST,
                'port': Config.REDIS_PORT,
                'db': Config.REDIS_DB,
                'socket_connect_timeout': 2,
                'socket_timeout': 2,
                'decode_responses': True,
            }
            if Config.REDIS_PASSWORD:
                kwargs['password'] = Config.REDIS_PASSWORD
            client = _redis_lib.Redis(**kwargs)
            client.ping()
            self._client = client
            logging.getLogger(__name__).info(
                f"Redis bridge connected: {Config.REDIS_HOST}:{Config.REDIS_PORT}"
            )
        except Exception as exc:
            logging.getLogger(__name__).warning(
                f"Redis unavailable ({exc}). "
                "Running in single-process mode (in-memory buffer + log fallback)."
            )
            self._client = None

    @property
    def available(self) -> bool:
        return self._client is not None

    def publish_event(self, event: DetectionEvent) -> None:
        if not self._client:
            return
        try:
            payload = json.dumps(event.to_dict())
            with self._lock:
                pipe = self._client.pipeline()
                pipe.lpush(_REDIS_KEY_EVENTS, payload)
                pipe.ltrim(_REDIS_KEY_EVENTS, 0, Config.REDIS_EVENT_LIST_MAX - 1)
                pipe.publish(_REDIS_CHANNEL, payload)
                pipe.execute()
        except Exception as exc:
            logging.getLogger(__name__).debug(f"Redis publish error: {exc}")

    def publish_rate(self, rate: float, threshold: float) -> None:
        if not self._client:
            return
        try:
            payload = json.dumps({
                'time': datetime.now().isoformat(),
                'rate': round(rate, 2),
                'threshold': round(threshold * 100, 2),
            })
            with self._lock:
                pipe = self._client.pipeline()
                pipe.lpush(_REDIS_KEY_RATES, payload)
                pipe.ltrim(_REDIS_KEY_RATES, 0, 99)
                pipe.execute()
        except Exception as exc:
            logging.getLogger(__name__).debug(f"Redis rate publish error: {exc}")

    def get_recent_events(self, count: int = 20) -> List[Dict]:
        if not self._client:
            return []
        try:
            raw_list = self._client.lrange(_REDIS_KEY_EVENTS, 0, count - 1)
            events = []
            for raw in raw_list:
                try:
                    events.append(json.loads(raw))
                except json.JSONDecodeError:
                    pass
            return events
        except Exception as exc:
            logging.getLogger(__name__).debug(f"Redis get_recent_events error: {exc}")
            return []

    def get_rate_history(self, count: int = 60) -> List[Dict]:
        """
        Fetch recent traffic-rate samples from Redis.

        Fix #21: fetch both keys in a single pipeline call to avoid a
        second round-trip when the rates key is empty.
        """
        if not self._client:
            return []
        try:
            with self._lock:
                pipe = self._client.pipeline()
                pipe.lrange(_REDIS_KEY_RATES, 0, count - 1)
                pipe.lrange(_REDIS_KEY_EVENTS, 0, 499)
                rates_raw, events_raw = pipe.execute()

            rates = []
            for raw in rates_raw:
                try:
                    rates.append(json.loads(raw))
                except json.JSONDecodeError:
                    pass
            if rates:
                return list(reversed(rates))

            # Fallback: derive per-second rate from event timestamps
            buckets: Dict[str, int] = {}
            for raw in events_raw:
                try:
                    evt = json.loads(raw)
                    if evt.get('event_type') in ('attack', 'normal'):
                        ts = evt.get('timestamp', '')
                        bucket = ts[11:19] if len(ts) >= 19 else ts
                        buckets[bucket] = buckets.get(bucket, 0) + 1
                except json.JSONDecodeError:
                    pass
            if buckets:
                derived = [
                    {'time': k, 'rate': float(v), 'threshold': 0.0}
                    for k, v in sorted(buckets.items())
                ]
                return derived[-count:]
            return []
        except Exception as exc:
            logging.getLogger(__name__).debug(f"Redis get_rate_history error: {exc}")
            return []

    def get_summary_stats(self) -> Optional[Dict]:
        if not self._client:
            return None
        try:
            raw_list = self._client.lrange(
                _REDIS_KEY_EVENTS, 0, Config.REDIS_EVENT_LIST_MAX - 1
            )
            total = attacks = normal = 0
            conf_sum = 0.0
            for raw in raw_list:
                try:
                    evt = json.loads(raw)
                    if evt.get('event_type') in ('attack', 'normal'):
                        total += 1
                        conf_sum += evt.get('confidence', 0.0)
                        if evt['event_type'] == 'attack':
                            attacks += 1
                        else:
                            normal += 1
                except json.JSONDecodeError:
                    pass
            attack_rate = (attacks / total * 100) if total > 0 else 0.0
            avg_conf = (conf_sum / total) if total > 0 else 0.0
            return {
                'total_predictions': total,
                'total_attacks': attacks,
                'total_normal': normal,
                'attack_rate': round(attack_rate, 1),
                'normal_rate': round(100 - attack_rate, 1),
                'avg_confidence': round(avg_conf, 2),
            }
        except Exception as exc:
            logging.getLogger(__name__).debug(f"Redis get_summary_stats error: {exc}")
            return None


# ── In-memory EventBuffer ──────────────────────────────────────────────────

class EventBuffer:
    """Thread-safe ring buffer for recent detection events."""

    def __init__(self, max_size: int = 500):
        self._buffer: deque = deque(maxlen=max_size)
        self._lock = threading.Lock()
        self._total_attacks = 0
        self._total_normal = 0
        self._total_predictions = 0
        self._confidence_sum = 0.0
        self._confidence_history: deque = deque(maxlen=100)
        self._rate_history: deque = deque(maxlen=100)

    def add_event(self, event: DetectionEvent) -> None:
        with self._lock:
            self._buffer.append(event)
            if event.event_type in ('attack', 'normal'):
                self._total_predictions += 1
                self._confidence_sum += event.confidence
                self._confidence_history.append({
                    'time': event.timestamp,
                    'confidence': event.confidence,
                    'threshold': event.threshold,
                    'is_attack': event.event_type == 'attack',
                })
                if event.event_type == 'attack':
                    self._total_attacks += 1
                else:
                    self._total_normal += 1
        get_redis_bridge().publish_event(event)

    def record_traffic_rate(self, rate: float, threshold: float) -> None:
        with self._lock:
            self._rate_history.append({
                'time': datetime.now().isoformat(),
                'rate': round(rate, 2),
                'threshold': round(threshold * 100, 2),
            })
        get_redis_bridge().publish_rate(rate, threshold)

    def get_recent_events(self, count: int = 20) -> List[Dict]:
        redis_events = get_redis_bridge().get_recent_events(count)
        if redis_events:
            return redis_events
        with self._lock:
            events = list(self._buffer)[-count:]
            return [e.to_dict() for e in reversed(events)]

    def get_confidence_history(self, count: int = 50) -> List[Dict]:
        """
        Get confidence history for charting.

        Reconstructed from the Redis event list so it is available in the
        dashboard container even though detection runs in a separate process.
        """
        redis_events = get_redis_bridge().get_recent_events(count)
        if redis_events:
            history = [
                {
                    'time': evt.get('timestamp', ''),
                    'confidence': evt.get('confidence', 0.0),
                    'threshold': evt.get('threshold', 0.0),
                    'is_attack': evt.get('event_type') == 'attack',
                }
                for evt in reversed(redis_events)
                if evt.get('event_type') in ('attack', 'normal')
            ]
            if history:
                return history[-count:]
        with self._lock:
            return list(self._confidence_history)[-count:]

    def get_rate_history(self, count: int = 50) -> List[Dict]:
        redis_rates = get_redis_bridge().get_rate_history(count)
        if redis_rates:
            return redis_rates
        with self._lock:
            return list(self._rate_history)[-count:]

    def get_summary_stats(self) -> Dict:
        redis_stats = get_redis_bridge().get_summary_stats()
        if redis_stats is not None:
            return redis_stats
        with self._lock:
            avg_conf = (
                self._confidence_sum / self._total_predictions
                if self._total_predictions > 0 else 0.0
            )
            attack_rate = (
                self._total_attacks / self._total_predictions * 100
                if self._total_predictions > 0 else 0.0
            )
            return {
                'total_predictions': self._total_predictions,
                'total_attacks': self._total_attacks,
                'total_normal': self._total_normal,
                'attack_rate': round(attack_rate, 1),
                'normal_rate': round(100 - attack_rate, 1),
                'avg_confidence': round(avg_conf, 2),
            }


# ── Global singletons ──────────────────────────────────────────────────────

_event_buffer: Optional[EventBuffer] = None
_redis_bridge: Optional[RedisBridge] = None
_logging_configured = False


def get_redis_bridge() -> RedisBridge:
    global _redis_bridge
    if _redis_bridge is None:
        _redis_bridge = RedisBridge()
    return _redis_bridge


def get_event_buffer() -> EventBuffer:
    global _event_buffer
    if _event_buffer is None:
        _event_buffer = EventBuffer()
    return _event_buffer


def setup_logging(service_name: str = 'detection') -> None:
    """
    Configure the centralised logging system.

    Fix #18: explicitly clear existing root-logger handlers before calling
    basicConfig so the call is never silently ignored (basicConfig is a no-op
    when handlers are already present, e.g. in Docker base images).

    Fix #19: the _logging_configured guard prevents re-configuration in the
    same process.  This is intentional — each service process calls
    setup_logging() once at startup.
    """
    global _logging_configured
    if _logging_configured:
        return

    Config.ensure_directories()

    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'

    log_files = {
        'detection': Config.DETECTION_LOG,
        'server': Config.SERVER_LOG,
        'dashboard': Config.LOGS_DIR / 'dashboard.log',
    }
    log_file = log_files.get(service_name, Config.DETECTION_LOG)

    root_logger = logging.getLogger()
    # Remove any pre-existing handlers so basicConfig is not a no-op
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    logging.basicConfig(
        level=getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO),
        format=log_format,
        datefmt=date_format,
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout),
        ],
    )

    _logging_configured = True


def record_prediction(
    is_attack: bool,
    confidence: float,
    threshold: float,
    rf_confidence: float = 0.0,
    svm_confidence: float = 0.0,
    source_ip: str = '',
    destination_ip: str = '',
) -> None:
    """Record a prediction event to the log and the event buffer."""
    logger = logging.getLogger('detection.prediction')
    event_type = 'attack' if is_attack else 'normal'

    if is_attack:
        msg = f"⚠️  DDoS ATTACK DETECTED! (Confidence: {confidence:.2%}, Threshold: {threshold:.2%})"
        logger.warning(msg)
    else:
        msg = f"✓ Normal traffic (Confidence: {confidence:.2%}, Threshold: {threshold:.2%})"
        logger.info(msg)

    event = DetectionEvent(
        event_type=event_type,
        confidence=round(confidence * 100, 2),
        threshold=round(threshold * 100, 2),
        rf_confidence=round(rf_confidence * 100, 2),
        svm_confidence=round(svm_confidence * 100, 2),
        source_ip=source_ip,
        destination_ip=destination_ip,
        message=msg,
    )
    buf = get_event_buffer()
    buf.add_event(event)

    # Always push a rate sample so the traffic-rate chart stays populated
    try:
        from app.adaptive_detection import get_adaptive_detector
        detector = get_adaptive_detector()
        buf.record_traffic_rate(detector.current_rate, detector.current_threshold)
    except Exception:
        pass


def record_adaptive_event(message: str, current_rate: float, threshold: float) -> None:
    """Record an adaptive threshold change event."""
    logging.getLogger('detection.adaptive').info(message)
    event = DetectionEvent(
        event_type='adaptive',
        confidence=0.0,
        threshold=round(threshold * 100, 2),
        message=message,
    )
    buf = get_event_buffer()
    buf.add_event(event)
    buf.record_traffic_rate(current_rate, threshold)
