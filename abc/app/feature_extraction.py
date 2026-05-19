"""
Module for extracting network flow features for DDoS detection.
"""
import logging
import threading
import numpy as np
from typing import Dict, Tuple, List, Optional
from dataclasses import dataclass, field

from config.settings import Config

logger = logging.getLogger(__name__)

# Minimum packets before prediction — sourced from Config so it can be
# overridden via the MIN_PACKETS_FOR_PREDICTION environment variable.
MIN_PACKETS_FOR_PREDICTION: int = Config.MIN_PACKETS_FOR_PREDICTION

# Predict every N packets after the minimum threshold is met.
# Set to 5 so predictions fire frequently enough to catch short-lived
# attack flows (Hulk opens many rapid connections that close quickly).
PREDICTION_INTERVAL: int = 5

# If a flow has been idle for longer than this (seconds), reset it.
# 10 seconds is enough — attack flows are short-lived and health checks
# arrive every 10s, so resetting at 10s keeps flows fresh.
FLOW_IDLE_RESET_TIMEOUT: float = 10.0

# TCP flag bitmasks (RFC 793 / RFC 3168)
_FLAG_FIN = 0x001
_FLAG_SYN = 0x002
_FLAG_RST = 0x004
_FLAG_PSH = 0x008
_FLAG_ACK = 0x010
_FLAG_URG = 0x020
_FLAG_ECE = 0x040
_FLAG_CWR = 0x080


@dataclass
class FlowFeatures:
    """Stores features of a network flow."""
    flow_id: Tuple[str, str, int, int]  # (src_ip, dst_ip, src_port, dst_port)
    start_time: float = 0.0
    end_time: float = 0.0
    total_fwd_packets: int = 0
    total_bwd_packets: int = 0
    total_length_of_fwd_packets: int = 0
    total_length_of_bwd_packets: int = 0
    fwd_packet_lengths: List[int] = field(default_factory=list)
    bwd_packet_lengths: List[int] = field(default_factory=list)
    fwd_iat_times: List[float] = field(default_factory=list)
    bwd_iat_times: List[float] = field(default_factory=list)
    last_fwd_packet_time: Optional[float] = None
    last_bwd_packet_time: Optional[float] = None
    syn_flag_count: int = 0
    fin_flag_count: int = 0
    rst_flag_count: int = 0
    psh_flag_count: int = 0
    ack_flag_count: int = 0
    urg_flag_count: int = 0
    ece_flag_count: int = 0
    cwe_flag_count: int = 0
    fwd_psh_flags: int = 0
    bwd_psh_flags: int = 0
    fwd_urg_flags: int = 0
    bwd_urg_flags: int = 0
    fwd_header_length: int = 0
    bwd_header_length: int = 0   # Fix #5: now accumulated in _update_backward_packet
    fwd_packets_sec: float = 0.0
    bwd_packets_sec: float = 0.0
    subflow_fwd_bytes: int = 0
    subflow_bwd_bytes: int = 0
    init_win_bytes_forward: int = 0
    init_win_bytes_backward: Optional[int] = None
    act_data_pkt_fwd: int = 0
    act_data_pkt_bwd: int = 0
    min_seg_size_forward: Optional[int] = None  # Fix #6: set in _update_forward_packet
    down_up_ratio: float = 0.0
    average_packet_size: float = 0.0

    # ── Active / Idle time tracking ──────────────────────────────────────────
    ACTIVE_TIMEOUT: float = field(default=2.0, init=False, repr=False, compare=False)
    _last_packet_time: Optional[float] = field(default=None, init=False, repr=False, compare=False)
    _active_start: Optional[float] = field(default=None, init=False, repr=False, compare=False)
    _active_durations: List[float] = field(default_factory=list, init=False, repr=False, compare=False)
    _idle_durations: List[float] = field(default_factory=list, init=False, repr=False, compare=False)


class FlowTracker:
    """Tracks and manages multiple network flows."""

    def __init__(self, timeout: float = 300.0):
        self.flows: Dict[Tuple[str, str, int, int], FlowFeatures] = {}
        self.timeout = timeout
        # Fix #9: protect the flows dict with a lock so concurrent packet
        # callbacks don't corrupt it or raise RuntimeError during iteration.
        self._lock = threading.Lock()

    def get_or_create_flow(
        self,
        flow_id: Tuple[str, str, int, int],
        packet_time: float,
        tcp_hdr_len: int,
        window_size: int
    ) -> FlowFeatures:
        """Get an existing flow or create a new one.

        If the existing flow has been idle for longer than
        FLOW_IDLE_RESET_TIMEOUT, discard it and start a fresh flow.
        This prevents stale flows from being endlessly extended when
        ephemeral ports are recycled, which would inflate the flow
        duration and dilute rate-based features.
        """
        with self._lock:
            if flow_id in self.flows:
                existing = self.flows[flow_id]
                idle_gap = packet_time - existing.end_time
                if idle_gap > FLOW_IDLE_RESET_TIMEOUT:
                    logger.debug(
                        f"Flow {flow_id} idle for {idle_gap:.1f}s — resetting"
                    )
                    del self.flows[flow_id]

            if flow_id not in self.flows:
                self.flows[flow_id] = FlowFeatures(
                    flow_id=flow_id,
                    start_time=packet_time,
                    end_time=packet_time,
                    last_fwd_packet_time=packet_time,
                    fwd_header_length=tcp_hdr_len,
                    init_win_bytes_forward=window_size
                )
            else:
                self.flows[flow_id].end_time = packet_time
            return self.flows[flow_id]

    def cleanup_expired_flows(self, current_time: float) -> None:
        """Remove expired flows."""
        with self._lock:
            expired = [
                fid for fid, flow in self.flows.items()
                if current_time - flow.end_time > self.timeout
            ]
            for fid in expired:
                del self.flows[fid]

    def get_flow(self, flow_id: Tuple[str, str, int, int]) -> Optional[FlowFeatures]:
        """Return a specific flow or None if it doesn't exist."""
        with self._lock:
            return self.flows.get(flow_id)


# Global tracker instance
_flow_tracker = FlowTracker()


def calculate_flow_features(packet) -> Optional[List[float]]:
    """
    Calculate network flow features from a packet.

    Returns None until the flow has accumulated MIN_PACKETS_FOR_PREDICTION
    packets, or on any parse error.

    Args:
        packet: Packet captured by pyshark

    Returns:
        List[float]: Feature vector, or None if not ready / error
    """
    try:
        if 'IP' not in packet or 'TCP' not in packet:
            return None

        src_ip = packet.ip.src
        dst_ip = packet.ip.dst
        src_port = int(packet.tcp.srcport)
        dst_port = int(packet.tcp.dstport)
        flow_id = (src_ip, dst_ip, src_port, dst_port)

        # Skip loopback self-connections (Docker health checks: 127.0.0.1→127.0.0.1).
        # These are not real traffic and produce misleading feature vectors.
        if src_ip == '127.0.0.1' and dst_ip == '127.0.0.1':
            return None

        # Fix #10: guard against sniff_time being None or non-datetime
        sniff_time = packet.sniff_time
        if sniff_time is None:
            return None
        packet_time = float(sniff_time.timestamp())

        tcp_hdr_len = int(packet.tcp.hdr_len)
        window_size = int(packet.tcp.window_size)

        flow = _flow_tracker.get_or_create_flow(
            flow_id, packet_time, tcp_hdr_len, window_size
        )

        # Fix #7: use IP payload length instead of total frame length.
        # packet.length includes the Ethernet header (~14-18 bytes extra).
        # packet.ip.len is the IP datagram length (header + payload), which
        # matches what CICFlowMeter uses for packet-length features.
        try:
            packet_length = int(packet.ip.len)
        except (AttributeError, ValueError):
            packet_length = int(packet.length)

        is_forward = packet.ip.src == flow_id[0]

        if is_forward:
            _update_forward_packet(flow, packet, packet_time, packet_length, tcp_hdr_len)
        else:
            _update_backward_packet(flow, packet, packet_time, packet_length, tcp_hdr_len)

        _calculate_derived_metrics(flow)
        _flow_tracker.cleanup_expired_flows(packet_time)

        total_packets = flow.total_fwd_packets + flow.total_bwd_packets
        if total_packets < MIN_PACKETS_FOR_PREDICTION:
            return None

        # Throttle predictions: only predict every PREDICTION_INTERVAL
        # packets after the minimum threshold is met.  The first eligible
        # packet (== MIN_PACKETS_FOR_PREDICTION) always triggers a
        # prediction; subsequent ones fire every PREDICTION_INTERVAL.
        packets_since_eligible = total_packets - MIN_PACKETS_FOR_PREDICTION
        if packets_since_eligible > 0 and packets_since_eligible % PREDICTION_INTERVAL != 0:
            return None

        return _extract_feature_vector(flow, dst_port)

    except Exception as e:
        # Fix #8: log parse errors at WARNING so they are visible in the log
        # without flooding it (they are not DEBUG-silent any more).
        logger.warning(f"Feature extraction error: {e}")
        return None


def _parse_tcp_flags(packet) -> int:
    """
    Parse TCP flags from a PyShark packet into an integer bitmask.

    Fix #4: PyShark exposes flags as a hex string like '0x018', NOT as a
    human-readable string like 'SYN ACK'.  Substring checks ('SYN' in flags)
    always return False.  We must parse the hex value and use bitmasks.
    """
    try:
        raw = packet.tcp.flags
        # PyShark may return '0x018', '0x18', or a plain decimal string
        if isinstance(raw, str):
            raw = raw.strip()
            return int(raw, 16) if raw.startswith('0x') or raw.startswith('0X') else int(raw, 0)
        return int(raw)
    except (ValueError, AttributeError):
        return 0


def _update_forward_packet(
    flow: FlowFeatures,
    packet,
    packet_time: float,
    packet_length: int,
    tcp_hdr_len: int,
) -> None:
    """Update forward packet information."""
    _update_active_idle(flow, packet_time)
    flow.total_fwd_packets += 1
    flow.total_length_of_fwd_packets += packet_length
    flow.fwd_packet_lengths.append(packet_length)

    if flow.last_fwd_packet_time is not None:
        iat = packet_time - flow.last_fwd_packet_time
        flow.fwd_iat_times.append(iat)
    flow.last_fwd_packet_time = packet_time

    flow.act_data_pkt_fwd += 1
    flow.subflow_fwd_bytes += packet_length
    flow.fwd_header_length += tcp_hdr_len

    # Fix #6: track minimum TCP segment size for forward packets
    payload_len = max(0, packet_length - tcp_hdr_len)
    if payload_len > 0:
        if flow.min_seg_size_forward is None or payload_len < flow.min_seg_size_forward:
            flow.min_seg_size_forward = payload_len

    # Fix #4: use bitmask checks on the parsed integer flags
    flags = _parse_tcp_flags(packet)
    if flags & _FLAG_SYN:
        flow.syn_flag_count += 1
    if flags & _FLAG_FIN:
        flow.fin_flag_count += 1
    if flags & _FLAG_RST:
        flow.rst_flag_count += 1
    if flags & _FLAG_PSH:
        flow.psh_flag_count += 1
        flow.fwd_psh_flags += 1
    if flags & _FLAG_ACK:
        flow.ack_flag_count += 1
    if flags & _FLAG_URG:
        flow.urg_flag_count += 1
        flow.fwd_urg_flags += 1
    if flags & _FLAG_ECE:
        flow.ece_flag_count += 1
    if flags & _FLAG_CWR:
        flow.cwe_flag_count += 1


def _update_backward_packet(
    flow: FlowFeatures,
    packet,
    packet_time: float,
    packet_length: int,
    tcp_hdr_len: int,
) -> None:
    """Update backward packet information."""
    _update_active_idle(flow, packet_time)
    flow.total_bwd_packets += 1
    flow.total_length_of_bwd_packets += packet_length
    flow.bwd_packet_lengths.append(packet_length)

    if flow.last_bwd_packet_time is not None:
        iat = packet_time - flow.last_bwd_packet_time
        flow.bwd_iat_times.append(iat)
    flow.last_bwd_packet_time = packet_time

    flow.act_data_pkt_bwd += 1
    flow.subflow_bwd_bytes += packet_length

    # Fix #5: accumulate backward header length (was always 0 before)
    flow.bwd_header_length += tcp_hdr_len

    if flow.init_win_bytes_backward is None:
        flow.init_win_bytes_backward = int(packet.tcp.window_size)

    # Fix #4: bitmask flag checks for backward packets
    flags = _parse_tcp_flags(packet)
    if flags & _FLAG_PSH:
        flow.bwd_psh_flags += 1
    if flags & _FLAG_URG:
        flow.bwd_urg_flags += 1


def _update_active_idle(flow: FlowFeatures, packet_time: float) -> None:
    """Update active/idle period tracking for the flow."""
    if flow._last_packet_time is None:
        flow._active_start = packet_time
        flow._last_packet_time = packet_time
        return

    gap = packet_time - flow._last_packet_time
    flow._last_packet_time = packet_time

    if gap > flow.ACTIVE_TIMEOUT:
        if flow._active_start is not None:
            prev_packet_time = packet_time - gap
            active_dur = prev_packet_time - flow._active_start
            if active_dur > 0:
                flow._active_durations.append(active_dur)
        flow._idle_durations.append(gap)
        flow._active_start = packet_time


def _calculate_derived_metrics(flow: FlowFeatures) -> None:
    """Calculate derived flow metrics."""
    if flow.total_bwd_packets > 0:
        flow.down_up_ratio = flow.total_fwd_packets / flow.total_bwd_packets

    total_packets = flow.total_fwd_packets + flow.total_bwd_packets
    if total_packets > 0:
        total_length = flow.total_length_of_fwd_packets + flow.total_length_of_bwd_packets
        flow.average_packet_size = total_length / total_packets

    duration = flow.end_time - flow.start_time
    if duration > 0:
        flow.fwd_packets_sec = flow.total_fwd_packets / duration
        flow.bwd_packets_sec = flow.total_bwd_packets / duration


def _extract_feature_vector(flow: FlowFeatures, dst_port: int) -> List[float]:
    """Extract the 77-feature vector from a flow."""
    all_packet_lengths = flow.fwd_packet_lengths + flow.bwd_packet_lengths
    all_iat_times = flow.fwd_iat_times + flow.bwd_iat_times
    duration = flow.end_time - flow.start_time

    # Active / Idle aggregates — close any open active period first
    active_durs = list(flow._active_durations)
    if flow._active_start is not None and flow._last_packet_time is not None:
        final_active = flow._last_packet_time - flow._active_start
        if final_active > 0:
            active_durs.append(final_active)

    idle_durs = list(flow._idle_durations)

    active_mean = float(np.mean(active_durs)) if active_durs else 0.0
    active_std  = float(np.std(active_durs))  if active_durs else 0.0
    active_max  = float(max(active_durs))      if active_durs else 0.0
    active_min  = float(min(active_durs))      if active_durs else 0.0

    idle_mean = float(np.mean(idle_durs)) if idle_durs else 0.0
    idle_std  = float(np.std(idle_durs))  if idle_durs else 0.0
    idle_max  = float(max(idle_durs))     if idle_durs else 0.0
    idle_min  = float(min(idle_durs))     if idle_durs else 0.0

    return [
        float(dst_port),
        duration,
        float(flow.total_fwd_packets),
        float(flow.total_bwd_packets),
        float(flow.total_length_of_fwd_packets),
        float(flow.total_length_of_bwd_packets),
        float(max(flow.fwd_packet_lengths)) if flow.fwd_packet_lengths else 0.0,
        float(min(flow.fwd_packet_lengths)) if flow.fwd_packet_lengths else 0.0,
        float(np.mean(flow.fwd_packet_lengths)) if flow.fwd_packet_lengths else 0.0,
        float(np.std(flow.fwd_packet_lengths)) if flow.fwd_packet_lengths else 0.0,
        float(max(flow.bwd_packet_lengths)) if flow.bwd_packet_lengths else 0.0,
        float(min(flow.bwd_packet_lengths)) if flow.bwd_packet_lengths else 0.0,
        float(np.mean(flow.bwd_packet_lengths)) if flow.bwd_packet_lengths else 0.0,
        float(np.std(flow.bwd_packet_lengths)) if flow.bwd_packet_lengths else 0.0,
        (flow.total_length_of_fwd_packets + flow.total_length_of_bwd_packets) / duration if duration > 0 else 0.0,
        (flow.total_fwd_packets + flow.total_bwd_packets) / duration if duration > 0 else 0.0,
        float(np.mean(all_iat_times)) if all_iat_times else 0.0,
        float(np.std(all_iat_times)) if all_iat_times else 0.0,
        float(max(all_iat_times)) if all_iat_times else 0.0,
        float(min(all_iat_times)) if all_iat_times else 0.0,
        float(sum(flow.fwd_iat_times)) if flow.fwd_iat_times else 0.0,
        float(np.mean(flow.fwd_iat_times)) if flow.fwd_iat_times else 0.0,
        float(np.std(flow.fwd_iat_times)) if flow.fwd_iat_times else 0.0,
        float(max(flow.fwd_iat_times)) if flow.fwd_iat_times else 0.0,
        float(min(flow.fwd_iat_times)) if flow.fwd_iat_times else 0.0,
        float(sum(flow.bwd_iat_times)) if flow.bwd_iat_times else 0.0,
        float(np.mean(flow.bwd_iat_times)) if flow.bwd_iat_times else 0.0,
        float(np.std(flow.bwd_iat_times)) if flow.bwd_iat_times else 0.0,
        float(max(flow.bwd_iat_times)) if flow.bwd_iat_times else 0.0,
        float(min(flow.bwd_iat_times)) if flow.bwd_iat_times else 0.0,
        float(flow.fwd_psh_flags),
        float(flow.bwd_psh_flags),
        float(flow.fwd_urg_flags),
        float(flow.bwd_urg_flags),
        float(flow.fwd_header_length),
        float(flow.bwd_header_length),
        flow.fwd_packets_sec,
        flow.bwd_packets_sec,
        float(min(all_packet_lengths)) if all_packet_lengths else 0.0,
        float(max(all_packet_lengths)) if all_packet_lengths else 0.0,
        float(np.mean(all_packet_lengths)) if all_packet_lengths else 0.0,
        float(np.std(all_packet_lengths)) if all_packet_lengths else 0.0,
        float(np.var(all_packet_lengths)) if all_packet_lengths else 0.0,
        float(flow.fin_flag_count),
        float(flow.syn_flag_count),
        float(flow.rst_flag_count),
        float(flow.psh_flag_count),
        float(flow.ack_flag_count),
        float(flow.urg_flag_count),
        float(flow.cwe_flag_count),
        float(flow.ece_flag_count),
        flow.down_up_ratio,
        flow.average_packet_size,
        float(np.mean(flow.fwd_packet_lengths)) if flow.fwd_packet_lengths else 0.0,
        float(np.mean(flow.bwd_packet_lengths)) if flow.bwd_packet_lengths else 0.0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0,  # Bulk features (not computed)
        float(flow.total_fwd_packets),
        float(flow.subflow_fwd_bytes),
        float(flow.total_bwd_packets),
        float(flow.subflow_bwd_bytes),
        float(flow.init_win_bytes_forward),
        float(flow.init_win_bytes_backward) if flow.init_win_bytes_backward is not None else 0.0,
        float(flow.act_data_pkt_fwd),
        float(flow.min_seg_size_forward) if flow.min_seg_size_forward is not None else 0.0,
        active_mean, active_std, active_max, active_min,
        idle_mean, idle_std, idle_max, idle_min,
    ]
