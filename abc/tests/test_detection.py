"""
Unit tests for the detection module.
"""
import unittest
from unittest.mock import Mock, patch, MagicMock
import numpy as np

from app.feature_extraction import FlowTracker, FlowFeatures, calculate_flow_features
from app.model_prediction import ModelPredictor, predict_attack


class TestFlowTracker(unittest.TestCase):
    """Tests for the flow tracker."""
    
    def setUp(self):
        """Initial setup for each test."""
        self.tracker = FlowTracker(timeout=300.0)
    
    def test_create_flow(self):
        """Test creation of new flow."""
        flow_id = ("192.168.1.1", "192.168.1.2", 12345, 80)
        flow = self.tracker.get_or_create_flow(flow_id, 1000.0, 20, 8192)
        
        self.assertIsInstance(flow, FlowFeatures)
        self.assertEqual(flow.flow_id, flow_id)
        self.assertEqual(flow.start_time, 1000.0)
        self.assertEqual(flow.init_win_bytes_forward, 8192)
    
    def test_get_existing_flow(self):
        """Test getting existing flow returns the same instance and updates end_time."""
        flow_id = ("192.168.1.1", "192.168.1.2", 12345, 80)
        flow1 = self.tracker.get_or_create_flow(flow_id, 1000.0, 20, 8192)
        flow2 = self.tracker.get_or_create_flow(flow_id, 1001.0, 20, 8192)
        
        self.assertIs(flow1, flow2)          # Same object in memory
        self.assertEqual(flow2.start_time, 1000.0)   # start_time unchanged
        self.assertEqual(flow2.end_time, 1001.0)     # end_time updated by second call
    
    def test_cleanup_expired_flows(self):
        """Test cleanup of expired flows."""
        flow_id = ("192.168.1.1", "192.168.1.2", 12345, 80)
        flow = self.tracker.get_or_create_flow(flow_id, 1000.0, 20, 8192)
        flow.end_time = 1000.0
        
        # Cleanup expired flows (timeout of 300s)
        self.tracker.cleanup_expired_flows(1400.0)  # 400s later
        
        self.assertIsNone(self.tracker.get_flow(flow_id))


class TestFeatureExtraction(unittest.TestCase):
    """Tests for feature extraction."""
    
    def test_calculate_flow_features_invalid_packet(self):
        """Test that non-IP/TCP packets return None.

        Fix #35: the check is 'IP' not in packet (uses __contains__), not
        attribute access.  We must mock __contains__ to return False for 'IP'
        rather than deleting the .ip attribute.
        """
        invalid_packet = Mock()
        # Simulate a packet that has no IP layer (e.g. ARP)
        invalid_packet.__contains__ = Mock(return_value=False)

        result = calculate_flow_features(invalid_packet)
        self.assertIsNone(result)
    
    @patch('app.feature_extraction._flow_tracker')
    def test_calculate_flow_features_valid_packet(self, mock_tracker):
        """Test extraction with valid packet that has enough accumulated packets."""
        packet = Mock()
        packet.ip.src = "192.168.1.1"
        packet.ip.dst = "192.168.1.2"
        packet.ip.len = "100"          # Fix: new code uses packet.ip.len (IP payload length)
        packet.tcp.srcport = "12345"
        packet.tcp.dstport = "80"
        packet.tcp.hdr_len = "20"
        packet.tcp.window_size = "8192"
        packet.tcp.flags = "0x018"
        packet.length = 100
        packet.sniff_time.timestamp.return_value = 1000.0

        packet.__contains__ = Mock(return_value=True)

        # Pre-populate the flow with 4 forward packets so the next packet
        # brings the total to exactly MIN_PACKETS_FOR_PREDICTION (5) —
        # the first eligible prediction point, which always triggers.
        flow = FlowFeatures(
            flow_id=("192.168.1.1", "192.168.1.2", 12345, 80),
            start_time=990.0,
            end_time=1000.0
        )
        flow.total_fwd_packets = 4
        flow.total_bwd_packets = 0
        flow.fwd_packet_lengths = [100, 120, 80, 110]
        flow.total_length_of_fwd_packets = sum(flow.fwd_packet_lengths)
        mock_tracker.get_or_create_flow.return_value = flow

        result = calculate_flow_features(packet)

        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 77)


class TestModelPrediction(unittest.TestCase):
    """Tests for model prediction."""
    
    @patch('app.model_prediction.Config')
    @patch('app.model_prediction.joblib.load')
    def test_model_predictor_initialization(self, mock_load, mock_config):
        """Test predictor initialization.

        Fix #36: decorator order was reversed — with stacked @patch decorators
        arguments are passed bottom-up, so the innermost decorator (closest to
        the function) maps to the first argument.  joblib.load must be the
        innermost patch so mock_load receives it.
        """
        mock_model = Mock()
        mock_model.predict.return_value = np.array([0])
        mock_model.predict_proba.return_value = np.array([[0.9, 0.1]])
        mock_model.classes_ = ['BENIGN', 'ATTACK']

        mock_svm = Mock()
        mock_svm.predict.return_value = np.array([0])
        mock_svm.predict_proba.return_value = np.array([[0.8, 0.2]])
        mock_svm.classes_ = [0, 1]

        mock_scaler = Mock()
        mock_scaler.n_features_in_ = 77
        mock_scaler.transform.return_value = np.array([[1.0] * 77])

        # joblib.load is called 3 times: RF model, SVM model, scaler
        mock_load.side_effect = [mock_model, mock_svm, mock_scaler]

        mock_config.MODEL_PATH.exists.return_value = True
        mock_config.SCALER_PATH.exists.return_value = True
        mock_config.SVM_MODEL_PATH.exists.return_value = True
        mock_config.HYBRID_MODE = True

        predictor = ModelPredictor()

        self.assertIsNotNone(predictor.model)
        self.assertIsNotNone(predictor.scaler)
    
    @patch('app.model_prediction.get_predictor')
    @patch('app.model_prediction.get_adaptive_detector')
    @patch('app.model_prediction.record_prediction')
    def test_predict_attack(self, mock_record, mock_get_adaptive, mock_get_predictor):
        """Test the full predict_attack pipeline.

        Fix #38: verify that record_prediction is called with the correct
        is_attack flag, not just that predictor.predict() was called.
        """
        mock_predictor = Mock()
        mock_predictor.predict.return_value = (1, 0.95, 0.90, 0.0)
        mock_get_predictor.return_value = mock_predictor

        mock_detector = Mock()
        mock_detector.evaluate.return_value = True   # is_attack = True
        mock_detector.current_threshold = 0.70
        mock_get_adaptive.return_value = mock_detector

        features = [0.0] * 77
        predict_attack(features)

        mock_predictor.predict.assert_called_once_with(features)
        mock_record.assert_called_once()
        call_kwargs = mock_record.call_args
        self.assertTrue(call_kwargs.kwargs.get('is_attack') or call_kwargs.args[0])
    
    def test_predict_attack_none_features(self):
        """Test prediction with None features."""
        with patch('app.model_prediction.logger') as mock_logger:
            predict_attack(None)
            mock_logger.warning.assert_called()


class TestIntegration(unittest.TestCase):
    """Basic integration tests."""
    
    def test_flow_features_dataclass(self):
        """Test that FlowFeatures is a valid dataclass."""
        flow = FlowFeatures(
            flow_id=("192.168.1.1", "192.168.1.2", 12345, 80),
            start_time=1000.0,
            end_time=1001.0
        )
        
        self.assertEqual(flow.start_time, 1000.0)
        self.assertEqual(flow.end_time, 1001.0)
        self.assertEqual(len(flow.fwd_packet_lengths), 0)


if __name__ == '__main__':
    unittest.main()
