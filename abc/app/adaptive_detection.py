"""
Module 5: Adaptive Detection Module
Dynamically adjusts detection thresholds based on changing network traffic patterns.
Uses an Exponential Moving Average (EMA) baseline for genuinely adaptive behavior.
"""
import time
import threading
import logging
from collections import deque
from typing import Optional
from config.settings import Config

logger = logging.getLogger(__name__)


class AdaptiveDetector:
    """Tracks traffic rates and dynamically tunes the detection threshold.

    Key design decisions (post-fix):
    ─────────────────────────────────
    1. **Threshold DECREASES during spikes** — a traffic spike is suspicious, so
       the system should become MORE sensitive (lower threshold) not less.
       Previously the threshold was *raised* during spikes, causing the model's
       high-confidence attack predictions (e.g. 80%) to be rejected because the
       threshold had climbed to 85%.

    2. **EMA baseline decays over idle time** — the EMA was only updated when
       packets arrived.  After an attack ended and traffic stopped, the EMA
       baseline froze at its peak value.  When a new attack started, the rate
       rarely exceeded 3× a massive frozen baseline, so the spike was never
       detected.  We now apply exponential decay proportional to idle time so
       the baseline drops back toward zero between attacks.

    3. **Zero time-span guard** — when multiple packets arrive in the same
       millisecond, ``time_span`` can be 0, producing a wildly inflated rate.
       We clamp to a minimum of 0.001 s.
    """

    # Number of traffic measurements to collect before the EMA baseline is
    # considered stable enough to start raising alerts.  During warm-up the
    # threshold is held at BASE_THRESHOLD and evaluate() always returns False
    # so no false positives fire while the baseline is still converging.
    WARMUP_SAMPLES: int = 10

    # Minimum confidence threshold — the adaptive system will never go below
    # this to avoid alerting on every single packet.
    MIN_THRESHOLD: float = 0.50

    def __init__(self):
        self.window_size = Config.ADAPTIVE_WINDOW
        self.base_threshold = Config.BASE_THRESHOLD
        self.max_threshold = Config.MAX_THRESHOLD
        self.spike_multiplier = Config.SPIKE_MULTIPLIER
        self.ema_alpha = Config.EMA_ALPHA

        self.traffic_history = deque()
        self.current_threshold = self.base_threshold

        self._ema_rate = 0.0
        self._ema_initialized = False
        self._sample_count = 0
        self._last_update_time: Optional[float] = None

        self.current_rate = 0.0
        self.baseline_rate = 0.0
        self.threshold_history: deque = deque(maxlen=100)

    def _cleanup_old_history(self, current_time: float) -> None:
        while self.traffic_history and current_time - self.traffic_history[0][0] > self.window_size:
            self.traffic_history.popleft()

    def _apply_idle_decay(self, current_time: float) -> None:
        """Decay the EMA baseline during idle periods.

        When no packets arrive for a while the baseline should drop toward
        zero.  We simulate the passage of ``n`` virtual zero-rate samples
        (one per second of idle time) by applying the EMA formula:
            ema = (1 - alpha)^n * ema
        This avoids accumulating a stale, inflated baseline between attacks.
        """
        if self._last_update_time is None:
            return
        idle_seconds = current_time - self._last_update_time
        if idle_seconds > 1.0 and self._ema_initialized:
            # Each idle second is one virtual sample with rate=0
            decay_steps = int(idle_seconds)
            decay_factor = (1 - self.ema_alpha) ** decay_steps
            self._ema_rate *= decay_factor
            self.baseline_rate = self._ema_rate
            logger.debug(
                f"EMA decayed over {decay_steps}s idle: baseline={self._ema_rate:.2f}"
            )

    def _update_ema_baseline(self, current_rate: float) -> float:
        if not self._ema_initialized:
            self._ema_rate = current_rate
            self._ema_initialized = True
        else:
            self._ema_rate = (
                self.ema_alpha * current_rate + (1 - self.ema_alpha) * self._ema_rate
            )
        self.baseline_rate = self._ema_rate
        return self._ema_rate

    def update_traffic_rate(self) -> float:
        """Record a new event and recalculate the adaptive threshold."""
        current_time = time.time()

        # Decay the EMA baseline for any idle period before this packet
        self._apply_idle_decay(current_time)

        self.traffic_history.append((current_time, 1))
        self._cleanup_old_history(current_time)

        if len(self.traffic_history) > 1:
            time_span = self.traffic_history[-1][0] - self.traffic_history[0][0]
            # Guard against zero time-span (packets arriving in the same ms)
            time_span = max(time_span, 0.001)
            current_rate = len(self.traffic_history) / time_span
        else:
            current_rate = 1.0

        self.current_rate = current_rate
        self._sample_count += 1
        self._last_update_time = current_time
        baseline = self._update_ema_baseline(current_rate)

        # Warm-up: hold threshold at base until EMA has stabilised
        if self._sample_count <= self.WARMUP_SAMPLES:
            self.current_threshold = self.base_threshold
            self.threshold_history.append({
                'time': current_time,
                'threshold': self.current_threshold,
                'rate': current_rate,
                'baseline': baseline,
            })
            return self.current_threshold

        spike_threshold = baseline * self.spike_multiplier

        if current_rate > spike_threshold and baseline > 0:
            # ── Traffic spike: LOWER the threshold to become MORE sensitive ──
            # The higher the spike ratio, the lower the threshold drops.
            ratio = min(current_rate / spike_threshold, 2.0)
            # Interpolate between base_threshold and MIN_THRESHOLD
            adjusted = max(self.base_threshold / ratio, self.MIN_THRESHOLD)
            if adjusted < self.current_threshold - 0.02:
                msg = (
                    f"📈 Traffic spike detected ({current_rate:.1f} pkts/sec, "
                    f"baseline={baseline:.1f}). "
                    f"Adaptive threshold LOWERED to {adjusted:.2f} (more sensitive)"
                )
                logger.info(msg)
                try:
                    from app.logging_monitor import record_adaptive_event
                    record_adaptive_event(msg, current_rate, adjusted)
                except ImportError:
                    pass
            self.current_threshold = adjusted
        else:
            # ── Normal traffic: restore threshold to base ──
            if self.current_threshold < self.base_threshold:
                msg = (
                    f"📉 Traffic normalized ({current_rate:.1f} pkts/sec, "
                    f"baseline={baseline:.1f}). "
                    f"Adaptive threshold restored to {self.base_threshold:.2f}"
                )
                logger.info(msg)
                try:
                    from app.logging_monitor import record_adaptive_event
                    record_adaptive_event(msg, current_rate, self.base_threshold)
                except ImportError:
                    pass
            self.current_threshold = self.base_threshold

        self.threshold_history.append({
            'time': current_time,
            'threshold': self.current_threshold,
            'rate': current_rate,
            'baseline': baseline,
        })
        return self.current_threshold

    def evaluate(self, confidence: float) -> bool:
        """
        Evaluate whether confidence exceeds the current adaptive threshold.

        During warm-up, always returns False (no alerts) so startup traffic
        (Docker health checks, TCP handshakes) never triggers false positives
        while the EMA baseline is still converging.
        """
        threshold = self.update_traffic_rate()
        if not Config.ADAPTIVE_MODE:
            threshold = Config.BASE_THRESHOLD
        # Suppress all alerts during warm-up period
        if self._sample_count <= self.WARMUP_SAMPLES:
            return False
        return confidence >= threshold

    def get_metrics(self) -> dict:
        warming_up = self._sample_count <= self.WARMUP_SAMPLES
        return {
            'current_rate': round(self.current_rate, 2),
            'baseline_rate': round(self.baseline_rate, 2),
            'current_threshold': round(self.current_threshold * 100, 2),
            'adaptive_mode': Config.ADAPTIVE_MODE,
            'warming_up': warming_up,
            'warmup_remaining': max(0, self.WARMUP_SAMPLES - self._sample_count),
            # During warm-up no alerts fire regardless of confidence
            'alerts_suppressed': warming_up,
        }


# ── Thread-safe singleton ──────────────────────────────────────────────────

_adaptive_detector: Optional[AdaptiveDetector] = None
_adaptive_detector_lock = threading.Lock()


def get_adaptive_detector() -> AdaptiveDetector:
    """
    Get the global AdaptiveDetector instance (thread-safe singleton).

    Fix #16: use double-checked locking to prevent two threads from both
    constructing an AdaptiveDetector simultaneously.
    """
    global _adaptive_detector
    if _adaptive_detector is None:
        with _adaptive_detector_lock:
            if _adaptive_detector is None:
                _adaptive_detector = AdaptiveDetector()
    return _adaptive_detector
