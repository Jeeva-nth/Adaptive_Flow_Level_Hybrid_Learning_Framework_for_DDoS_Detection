"""
Module 7: Report Generation Module
Analyzes logged data and generates summarized reports of detection performance.
Supports console output, JSON export, and dashboard-friendly data retrieval.
"""
import re
import json
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from config.settings import Config


class DetectionReport:
    """Generates reports from detection logs."""
    
    def __init__(self, log_file: Path = None):
        """
        Initialize report generator.
        
        Args:
            log_file: Path to detection log file
        """
        self.log_file = log_file or Config.DETECTION_LOG
        self.predictions: List[Dict] = []
        self.stats: Dict = defaultdict(int)
    
    def parse_logs(self, window_seconds: Optional[int] = None) -> None:
        """
        Parse detection logs and extract predictions.
        
        Args:
            window_seconds: If set, only parse logs within this time window.
                            None means parse all logs.
        """
        if not self.log_file.exists():
            return
        
        # Reset state
        self.predictions = []
        self.stats = defaultdict(int)
        
        # Patterns to match - using ASCII-safe patterns to avoid encoding issues on Windows
        # Match both emoji and ASCII variants for robustness
        attack_pattern = re.compile(
            r'(?:⚠️|WARNING:)?\s*DDoS ATTACK DETECTED!.*?\(Confidence:\s+([\d.]+)%'
        )
        normal_pattern = re.compile(
            r'(?:✓|OK:)?\s*Normal traffic.*?\(Confidence:\s+([\d.]+)%'
        )
        threshold_pattern = re.compile(r'Threshold:\s+([\d.]+)%')
        timestamp_pattern = re.compile(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})')
        
        # Calculate cutoff time if windowed
        cutoff_time = None
        if window_seconds is not None:
            cutoff_time = datetime.now() - timedelta(seconds=window_seconds)
        
        try:
            # Explicitly use UTF-8 encoding with error handling for cross-platform compatibility
            with open(self.log_file, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except Exception:
            return
        
        for line in lines:
            # Extract timestamp
            ts_match = timestamp_pattern.search(line)
            if not ts_match:
                continue
            
            current_timestamp = ts_match.group(1)
            
            # If windowed, skip old entries
            if cutoff_time is not None:
                try:
                    line_time = datetime.strptime(current_timestamp, '%Y-%m-%d %H:%M:%S')
                    if line_time < cutoff_time:
                        continue
                except ValueError:
                    continue
            
            # Extract threshold
            thresh_match = threshold_pattern.search(line)
            threshold_val = float(thresh_match.group(1)) if thresh_match else 0.0
            
            # Check for attack detection
            attack_match = attack_pattern.search(line)
            if attack_match:
                confidence = float(attack_match.group(1))
                self.predictions.append({
                    'timestamp': current_timestamp,
                    'type': 'ATTACK',
                    'confidence': confidence,
                    'threshold': threshold_val,
                    'line': line.strip()
                })
                self.stats['total_attacks'] += 1
                self.stats['total_predictions'] += 1
                continue
            
            # Check for normal traffic
            normal_match = normal_pattern.search(line)
            if normal_match:
                confidence = float(normal_match.group(1))
                self.predictions.append({
                    'timestamp': current_timestamp,
                    'type': 'NORMAL',
                    'confidence': confidence,
                    'threshold': threshold_val,
                    'line': line.strip()
                })
                self.stats['total_normal'] += 1
                self.stats['total_predictions'] += 1
                continue
    
    def generate_summary(self) -> Dict:
        """Generate summary statistics."""
        if not self.predictions:
            return {
                'total_predictions': 0,
                'message': 'No predictions found in logs'
            }
        
        attack_confidences = [
            p['confidence'] for p in self.predictions if p['type'] == 'ATTACK'
        ]
        normal_confidences = [
            p['confidence'] for p in self.predictions if p['type'] == 'NORMAL'
        ]
        
        summary = {
            'total_predictions': len(self.predictions),
            'attacks_detected': self.stats['total_attacks'],
            'normal_traffic': self.stats['total_normal'],
            # Fix #32: use self.stats['total_predictions'] as denominator for
            # consistency — it equals len(self.predictions) but is more robust
            # if a future code path appends to predictions without updating stats.
            'attack_rate': (
                self.stats['total_attacks'] / self.stats['total_predictions'] * 100
                if self.stats['total_predictions'] > 0 else 0
            ),
            'normal_rate': (
                self.stats['total_normal'] / self.stats['total_predictions'] * 100
                if self.stats['total_predictions'] > 0 else 0
            ),
        }
        
        if attack_confidences:
            summary['avg_attack_confidence'] = round(sum(attack_confidences) / len(attack_confidences), 2)
            summary['max_attack_confidence'] = round(max(attack_confidences), 2)
            summary['min_attack_confidence'] = round(min(attack_confidences), 2)
        
        if normal_confidences:
            summary['avg_normal_confidence'] = round(sum(normal_confidences) / len(normal_confidences), 2)
            summary['max_normal_confidence'] = round(max(normal_confidences), 2)
            summary['min_normal_confidence'] = round(min(normal_confidences), 2)
        
        return summary
    
    def generate_summary_dict(self, window_seconds: Optional[int] = None) -> Dict:
        """
        Generate a dashboard-friendly summary dictionary.
        
        Args:
            window_seconds: Time window for the report (None = all time)
        
        Returns:
            Dict with summary statistics and recent predictions
        """
        self.parse_logs(window_seconds=window_seconds)
        summary = self.generate_summary()
        summary['recent_predictions'] = self.predictions[-10:] if self.predictions else []
        return summary
    
    def print_report(self) -> None:
        """Print formatted report to console.

        Fix #30: call parse_logs() first so self.predictions is populated
        even when print_report() is called directly without a prior
        parse_logs() call.
        """
        # Ensure logs are parsed before generating the summary
        if not self.predictions:
            self.parse_logs()

        print("=" * 70)
        print("DDoS Detection Report")
        print("=" * 70)
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Log file: {self.log_file}")
        print()
        
        summary = self.generate_summary()
        
        if summary.get('total_predictions', 0) == 0:
            print("⚠️  No predictions found in logs.")
            print("   Make sure the detection system is running and has processed traffic.")
            return
        
        print("📊 SUMMARY STATISTICS")
        print("-" * 70)
        print(f"Total Predictions:     {summary['total_predictions']}")
        print(f"Attacks Detected:      {summary['attacks_detected']} ({summary['attack_rate']:.1f}%)")
        print(f"Normal Traffic:        {summary['normal_traffic']} ({summary['normal_rate']:.1f}%)")
        print()
        
        if summary.get('avg_attack_confidence'):
            print("🎯 ATTACK DETECTION CONFIDENCE")
            print("-" * 70)
            print(f"Average: {summary['avg_attack_confidence']:.2f}%")
            print(f"Maximum: {summary['max_attack_confidence']:.2f}%")
            print(f"Minimum: {summary['min_attack_confidence']:.2f}%")
            print()
        
        if summary.get('avg_normal_confidence'):
            print("✅ NORMAL TRAFFIC CONFIDENCE")
            print("-" * 70)
            print(f"Average: {summary['avg_normal_confidence']:.2f}%")
            print(f"Maximum: {summary['max_normal_confidence']:.2f}%")
            print(f"Minimum: {summary['min_normal_confidence']:.2f}%")
            print()
        
        print("📋 RECENT PREDICTIONS (Last 10)")
        print("-" * 70)
        recent = self.predictions[-10:] if len(self.predictions) > 10 else self.predictions
        for pred in recent:
            status = "🔴 ATTACK" if pred['type'] == 'ATTACK' else "🟢 NORMAL"
            print(f"{pred['timestamp']} | {status} | Confidence: {pred['confidence']:.2f}%")
        
        print()
        print("=" * 70)
    
    def save_json_report(self, output_file: Path = None) -> None:
        """Save report as JSON."""
        if output_file is None:
            output_file = Config.LOGS_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report_data = {
            'generated_at': datetime.now().isoformat(),
            'log_file': str(self.log_file),
            'summary': self.generate_summary(),
            'predictions': self.predictions
        }
        
        # Fix #31: specify UTF-8 encoding to avoid UnicodeEncodeError on Windows
        # when log lines contain emoji characters (⚠️, ✓, etc.)
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"📄 Report saved to: {output_file}")


def main():
    """Main function to generate report."""
    report = DetectionReport()
    report.parse_logs()
    report.print_report()
    
    # Ask if user wants to save JSON report
    try:
        save_json = input("\nSave JSON report? (y/n): ").lower().strip()
        if save_json == 'y':
            report.save_json_report()
    except (EOFError, KeyboardInterrupt):
        pass


if __name__ == '__main__':
    main()
