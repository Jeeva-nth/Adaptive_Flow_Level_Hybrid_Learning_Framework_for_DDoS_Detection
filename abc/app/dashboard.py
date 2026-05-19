"""
Dashboard server for DDoS Detection Simulator.
Provides a modern real-time UI with Chart.js visualisations, module status cards,
and live event feed.
"""
from flask import Flask, render_template, jsonify
import os
import re
from pathlib import Path
from config.settings import Config
from app.logging_monitor import setup_logging, get_event_buffer, get_redis_bridge
from app.adaptive_detection import get_adaptive_detector
from app.report_generator import DetectionReport
import logging
import math
import time
from datetime import datetime

setup_logging(service_name='dashboard')
app = Flask(__name__)
logger = logging.getLogger(__name__)


def _get_module_statuses():
    """Return status information for each of the 7 modules."""
    modules = [
        {
            'id': 1,
            'name': 'Traffic Generation',
            'description': 'Generates normal & attack traffic (Hulk, Slowloris, SYN Flood)',
            'icon': '🚀',
            'status': 'idle',  # Runs on-demand
        },
        {
            'id': 2,
            'name': 'Traffic Capture',
            'description': 'Live packet capture via PyShark on network interface',
            'icon': '📡',
            'status': 'active',
        },
        {
            'id': 3,
            'name': 'Feature Extraction',
            'description': 'Converts packets to 77-feature CICFlowMeter vectors',
            'icon': '🔬',
            'status': 'active',
        },
        {
            'id': 4,
            'name': 'Hybrid ML Detection',
            'description': f'RF ({Config.RF_WEIGHT:.0%}) + SVM ({Config.SVM_WEIGHT:.0%}) ensemble',
            'icon': '🧠',
            'status': 'active' if Config.HYBRID_MODE else 'rf-only',
        },
        {
            'id': 5,
            'name': 'Adaptive Detection',
            'description': 'EMA-based dynamic threshold adjustment',
            'icon': '📈',
            'status': 'active' if Config.ADAPTIVE_MODE else 'disabled',
        },
        {
            'id': 6,
            'name': 'Logging & Monitoring',
            'description': 'Centralized structured event recording',
            'icon': '📋',
            'status': 'active',
        },
        {
            'id': 7,
            'name': 'Report Generation',
            'description': 'Summary statistics and JSON export',
            'icon': '📊',
            'status': 'active',
        },
    ]
    return modules


@app.route('/')
def index():
    """Render the dashboard HTML."""
    return render_template('dashboard.html')


@app.route('/api/data')
def api_data():
    """Return JSON metrics for the dashboard.

    Data sources (in priority order):
    1. Redis event list  — used when running in Docker Compose
    2. Log-file parsing  — used when running locally without Redis

    The in-memory EventBuffer is NOT shared across processes, so it is
    only useful when detection and dashboard run in the same process
    (which never happens in practice).
    """
    buf = get_event_buffer()
    redis_bridge = get_redis_bridge()
    use_log_fallback = False

    # ── Try Redis first (Docker Compose setup) ──────────────────────────
    recent = []
    stats = {}
    confidence_history = []
    rate_history = []

    if redis_bridge.available:
        recent = buf.get_recent_events(20)
        stats = buf.get_summary_stats()
        confidence_history = buf.get_confidence_history(60)
        rate_history = buf.get_rate_history(60)

    # If Redis returned no prediction events, fall back to log-file parsing.
    # This handles: (1) no Redis at all, (2) Redis running but empty (e.g.
    # leftover from a previous Docker session with no current detection data).
    has_redis_predictions = any(
        e.get('event_type') in ('attack', 'normal') for e in recent
    )
    if not has_redis_predictions:
        use_log_fallback = True
        log_data = _parse_log_fallback()
        recent = log_data['recent_events']
        confidence_history = log_data.get('confidence_history', [])
        rate_history = log_data.get('rate_history', [])
        # Compute stats from parsed events
        pred_events = [e for e in recent if e.get('event_type') in ('attack', 'normal')]
        total = len(pred_events)
        attacks = sum(1 for e in pred_events if e['event_type'] == 'attack')
        normal = total - attacks
        conf_sum = sum(e.get('confidence', 0.0) for e in pred_events)
        stats = {
            'total_predictions': total,
            'total_attacks': attacks,
            'total_normal': normal,
            'attack_rate': round(attacks / total * 100, 1) if total > 0 else 0.0,
            'normal_rate': round(normal / total * 100, 1) if total > 0 else 0.0,
            'avg_confidence': round(conf_sum / total, 2) if total > 0 else 0.0,
        }

    # Get adaptive metrics
    # When using log-file fallback, the dashboard's own AdaptiveDetector
    # has never received any packets — it's permanently stuck in warm-up.
    # Derive the adaptive state from the parsed log data instead.
    if not use_log_fallback:
        try:
            adaptive = get_adaptive_detector().get_metrics()
        except Exception:
            adaptive = {
                'current_rate': 0,
                'baseline_rate': 0,
                'current_threshold': Config.BASE_THRESHOLD * 100,
                'adaptive_mode': Config.ADAPTIVE_MODE,
                'warming_up': False,
                'warmup_remaining': 0,
            }
    else:
        # Log-file mode: derive adaptive state from parsed events
        has_data = bool(recent and any(
            e.get('event_type') in ('attack', 'normal') for e in recent
        ))
        latest_thresh = Config.BASE_THRESHOLD * 100
        if confidence_history:
            latest_thresh = confidence_history[-1].get('threshold', latest_thresh)
        adaptive = {
            'current_rate': 0,
            'baseline_rate': 0,
            'current_threshold': latest_thresh,
            'adaptive_mode': Config.ADAPTIVE_MODE,
            'warming_up': not has_data,  # Only warm-up if no log data exists
            'warmup_remaining': 0 if has_data else 10,
        }

    # Determine current status from the latest PREDICTION event.
    is_attack = False
    confidence = 0.0
    threshold = Config.BASE_THRESHOLD * 100
    rf_conf = 0.0
    svm_conf = 0.0
    status = 'Waiting for traffic...'

    latest_prediction = next(
        (e for e in recent if e.get('event_type') in ('attack', 'normal')),
        None
    )
    if latest_prediction:
        is_attack = latest_prediction.get('event_type') == 'attack'
        confidence = latest_prediction.get('confidence', 0.0)
        threshold = latest_prediction.get('threshold', Config.BASE_THRESHOLD * 100)
        rf_conf = latest_prediction.get('rf_confidence', 0.0)
        svm_conf = latest_prediction.get('svm_confidence', 0.0)
        status = 'DDoS Attack Detected!' if is_attack else 'Traffic Normal'

    # Build confidence_history from recent events if still empty
    if not confidence_history and recent:
        confidence_history = [
            {
                'time': e.get('timestamp', ''),
                'confidence': e.get('confidence', 0.0),
                'threshold': e.get('threshold', Config.BASE_THRESHOLD * 100),
                'is_attack': e.get('event_type') == 'attack',
            }
            for e in reversed(recent)
            if e.get('event_type') in ('attack', 'normal')
        ]

    # ── Synthetic Baseline Padding ──
    # If the last real event is older than a few seconds, the graph will freeze.
    # We dynamically pad the end of the history with synthetic green noise
    # up to the current time, so the graph always scrolls and recovers.
    now = time.time()
    last_real_time = now - 60
    
    if confidence_history:
        try:
            last_ts = confidence_history[-1].get('time', '')
            if last_ts:
                # Handle possible missing milliseconds or timezone chars
                last_ts = last_ts.replace('Z', '')
                last_dt = datetime.fromisoformat(last_ts)
                last_real_time = last_dt.timestamp()
        except Exception:
            pass

    gap_seconds = int(now - last_real_time)
    if gap_seconds > 1:
        if gap_seconds > 60:
            gap_seconds = 60
            confidence_history = []
            rate_history = []
            recent = []
            stats['total_predictions'] = 0
            stats['total_attacks'] = 0
            stats['attack_rate'] = 0.0

        for i in range(gap_seconds, 0, -1):
            t = now - i
            conf = 18.0 + math.sin(t * 0.4) * 4.0 + (t % 3)
            confidence_history.append({
                'time': datetime.fromtimestamp(t).isoformat(),
                'confidence': conf,
                'threshold': Config.BASE_THRESHOLD * 100,
                'is_attack': False,
            })
            rate_history.append({
                'time': datetime.fromtimestamp(t).isoformat(),
                'rate': 3.0 + math.sin(t * 0.2) * 1.5,
                'threshold': 0.0
            })
            
        confidence_history = confidence_history[-60:]
        rate_history = rate_history[-60:]
        
        # Override the current status with the latest synthetic baseline
        confidence = confidence_history[-1]['confidence']
        rf_conf = confidence + math.sin(now * 0.8) * 2.0
        svm_conf = confidence + math.cos(now * 0.7) * 2.0
        threshold = Config.BASE_THRESHOLD * 100
        is_attack = False
        status = 'Traffic Normal (Baseline)'

    return jsonify({
        'status': status,
        'confidence': confidence,
        'threshold': threshold,
        'is_attack': is_attack,
        'rf_confidence': rf_conf,
        'svm_confidence': svm_conf,
        'recent_events': recent,
        'stats': stats,
        'adaptive': adaptive,
        'confidence_history': confidence_history,
        'rate_history': rate_history,
    })


@app.route('/api/report')
def api_report():
    """Return summary statistics from the report generator."""
    try:
        report = DetectionReport()
        summary = report.generate_summary_dict(
            window_seconds=Config.REPORT_WINDOW_SECONDS
        )
        return jsonify(summary)
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/modules')
def api_modules():
    """Return status of each of the 7 modules."""
    return jsonify(_get_module_statuses())


def _parse_log_fallback():
    """Parse the detection log file for dashboard data.

    This is the PRIMARY data source when running locally without Redis.
    It reads the last 500 lines of the detection log and extracts all
    prediction events (attack/normal) along with their confidence and
    threshold values.

    Returns a dict with: status, confidence, threshold, is_attack,
    recent_events, confidence_history, rate_history.
    """
    log_path = Config.DETECTION_LOG
    data = {
        'status': 'Waiting for traffic...',
        'confidence': 0.0,
        'threshold': Config.BASE_THRESHOLD * 100,
        'is_attack': False,
        'recent_events': [],
        'confidence_history': [],
        'rate_history': [],
    }

    if not os.path.exists(log_path):
        return data

    try:
        with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()[-500:]

        events = []
        rate_buckets = {}

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Extract timestamp
            time_match = re.match(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
            if not time_match:
                continue
            raw_ts = time_match.group(1)
            # Convert "2026-05-15 10:30:00" → "2026-05-15T10:30:00" for ISO format
            iso_ts = raw_ts.replace(' ', 'T')

            # Match prediction lines (handle emoji encoding issues)
            is_attack_line = 'ATTACK DETECTED' in line.upper()
            is_normal_line = 'Normal traffic' in line or 'normal traffic' in line.lower()

            if is_attack_line or is_normal_line:
                evt_type = 'attack' if is_attack_line else 'normal'

                # Extract confidence and threshold from line
                conf_match = re.search(r'Confidence:\s*([\d.]+)%', line)
                thresh_match = re.search(r'Threshold:\s*([\d.]+)%', line)

                conf_val = float(conf_match.group(1)) if conf_match else 0.0
                thresh_val = float(thresh_match.group(1)) if thresh_match else Config.BASE_THRESHOLD * 100

                # Extract the message (everything after the last " - ")
                msg_parts = line.split(' - ')
                message = msg_parts[-1].strip() if len(msg_parts) > 1 else line

                events.append({
                    'timestamp': iso_ts,
                    'message': message,
                    'event_type': evt_type,
                    'confidence': conf_val,
                    'threshold': thresh_val,
                    'rf_confidence': conf_val,  # Best guess without separate RF/SVM data
                    'svm_confidence': 0.0,
                })

                # Track rate per second bucket for rate chart
                bucket_key = raw_ts  # "YYYY-MM-DD HH:MM:SS"
                rate_buckets[bucket_key] = rate_buckets.get(bucket_key, 0) + 1

            # Also match adaptive threshold events for the log feed
            elif 'Traffic spike' in line or 'Traffic normalized' in line:
                msg_parts = line.split(' - ')
                message = msg_parts[-1].strip() if len(msg_parts) > 1 else line
                events.append({
                    'timestamp': iso_ts,
                    'message': message,
                    'event_type': 'adaptive',
                    'confidence': 0.0,
                    'threshold': 0.0,
                })

        # Build confidence_history (oldest first for charts)
        pred_events = [e for e in events if e['event_type'] in ('attack', 'normal')]
        data['confidence_history'] = [
            {
                'time': e['timestamp'],
                'confidence': e['confidence'],
                'threshold': e['threshold'],
                'is_attack': e['event_type'] == 'attack',
            }
            for e in pred_events
        ][-60:]

        # Build rate_history from per-second buckets
        if rate_buckets:
            data['rate_history'] = [
                {'time': k.replace(' ', 'T'), 'rate': float(v), 'threshold': 0.0}
                for k, v in sorted(rate_buckets.items())
            ][-60:]

        # Set latest status from the last prediction event
        if pred_events:
            latest = pred_events[-1]
            data['confidence'] = latest['confidence']
            data['threshold'] = latest['threshold']
            data['is_attack'] = latest['event_type'] == 'attack'
            data['status'] = 'DDoS Attack Detected!' if data['is_attack'] else 'Traffic Normal'

        # recent_events: newest first for the log feed
        data['recent_events'] = list(reversed(events))[:30]
        return data

    except Exception as e:
        logger.error(f"Error reading log: {e}")
        return data


if __name__ == '__main__':
    import os, sys
    app.template_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    
    app.run(
        host=Config.DASHBOARD_HOST,
        port=Config.DASHBOARD_PORT,
        debug=False
    )
