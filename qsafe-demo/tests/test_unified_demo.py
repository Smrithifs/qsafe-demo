#!/usr/bin/env python3
"""
Comprehensive test suite for Q-SAFE Unified Demo Dashboard Integration
Tests all major functionality including UX controls, PCAP generation, MITM detection, and keygen events.
"""

import pytest
import json
import time
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unified_demo import app, qsafe_state, log_event, socketio

@pytest.fixture
def client():
    """Create test client"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture
def reset_state():
    """Reset global state before each test"""
    global qsafe_state
    qsafe_state.update({
        'devices': {'A': {'status': 'offline', 'keys': None}, 'B': {'status': 'offline', 'keys': None}},
        'satellite_online': True,
        'messages': [],
        'attacks': [],
        'mission_phase': 'INIT',
        'mission_running': False,
        'logs': [],
        'stats': {
            'messages_sent': 0,
            'attacks_blocked': 0,
            'integrity_score': 100
        }
    })

class TestRefreshButton:
    """Test refresh button functionality and state management"""
    
    def test_refresh_status_endpoint(self, client, reset_state):
        """Test /api/events/latest endpoint returns proper data"""
        response = client.get('/api/events/latest')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'events' in data
        assert 'stats' in data
        assert 'devices' in data
        assert 'mission_phase' in data
        assert data['mission_phase'] == 'INIT'
    
    def test_refresh_with_events(self, client, reset_state):
        """Test refresh returns recent events"""
        # Add some test events
        log_event('SECURE', 'Test event 1', 'TEST')
        log_event('WARNING', 'Test event 2', 'TEST')
        
        response = client.get('/api/events/latest')
        data = json.loads(response.data)
        
        assert len(data['events']) >= 2
        assert any('Test event 1' in event['message'] for event in data['events'])
        assert any('Test event 2' in event['message'] for event in data['events'])

class TestKeyGeneration:
    """Test key generation with device.keygen events and fingerprints"""
    
    def test_keygen_success(self, client, reset_state):
        """Test successful key generation"""
        response = client.post('/api/device/keygen', 
                             json={'device_id': 'A'})
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'key_data' in data
        assert data['key_data']['device_id'] == 'A'
        assert 'fingerprint' in data['key_data']
        assert 'key_id' in data['key_data']
        assert data['key_data']['alg'] == 'RSA-2048 + Kyber-768'
    
    def test_keygen_invalid_device(self, client, reset_state):
        """Test key generation with invalid device ID"""
        response = client.post('/api/device/keygen', 
                             json={'device_id': 'X'})
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Invalid device_id' in data['error']
    
    def test_keygen_missing_device_id(self, client, reset_state):
        """Test key generation without device_id"""
        response = client.post('/api/device/keygen', json={})
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Missing device_id' in data['error']
    
    def test_keygen_regeneration_warning(self, client, reset_state):
        """Test key regeneration shows warning"""
        # Generate keys first time
        client.post('/api/device/keygen', json={'device_id': 'A'})
        
        # Generate again - should warn but succeed
        response = client.post('/api/device/keygen', json={'device_id': 'A'})
        assert response.status_code == 200
        
        # Check logs for warning
        assert any('already exist' in log['message'] for log in qsafe_state['logs'])

class TestMITMControls:
    """Test MITM control functionality with red node animation and tamper detection"""
    
    def test_mitm_decrypt_attack(self, client, reset_state):
        """Test MITM decrypt attack simulation"""
        response = client.post('/api/attack/simulate', 
                             json={'attack_type': 'decrypt'})
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'attack_data' in data
        assert data['attack_data']['attack_type'] == 'decrypt'
        assert 'FAILED - Post-quantum encryption resistant' in data['attack_data']['result']
    
    def test_mitm_tamper_attack(self, client, reset_state):
        """Test MITM tamper attack simulation"""
        response = client.post('/api/attack/simulate', 
                             json={'attack_type': 'tamper'})
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'DETECTED - Authentication tag mismatch' in data['attack_data']['result']
    
    def test_mitm_replay_attack(self, client, reset_state):
        """Test MITM replay attack simulation"""
        response = client.post('/api/attack/simulate', 
                             json={'attack_type': 'replay'})
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'BLOCKED - Nonce validation failed' in data['attack_data']['result']
    
    def test_mitm_attack_logging(self, client, reset_state):
        """Test MITM attacks are properly logged"""
        client.post('/api/attack/simulate', json={'attack_type': 'decrypt'})
        
        # Check for attack and defense logs
        attack_logs = [log for log in qsafe_state['logs'] if log['level'] == 'BREACH']
        defense_logs = [log for log in qsafe_state['logs'] if 'Attack blocked' in log['message']]
        
        assert len(attack_logs) > 0
        assert len(defense_logs) > 0
        assert qsafe_state['stats']['attacks_blocked'] > 0

class TestMessageSending:
    """Test message sending with encryption/signing/packet bytes"""
    
    def test_message_send_success(self, client, reset_state):
        """Test successful message sending with crypto details"""
        # Generate keys first
        client.post('/api/device/keygen', json={'device_id': 'A'})
        client.post('/api/device/keygen', json={'device_id': 'B'})
        
        response = client.post('/api/message/send', json={
            'from': 'A',
            'to': 'B',
            'message': 'Test secure message'
        })
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'message_data' in data
        assert data['message_data']['from'] == 'A'
        assert data['message_data']['to'] == 'B'
        assert 'payload_hex' in data['message_data']
        assert 'signature_hex' in data['message_data']
        assert len(data['message_data']['payload_hex']) > 0
        assert len(data['message_data']['signature_hex']) > 0
    
    def test_message_send_no_keys(self, client, reset_state):
        """Test message sending without keys fails"""
        response = client.post('/api/message/send', json={
            'from': 'A',
            'to': 'B',
            'message': 'Test message'
        })
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert 'error' in data
        assert 'keys not generated' in data['error']
    
    def test_message_validation(self, client, reset_state):
        """Test message validation (empty, too long, etc.)"""
        # Generate keys
        client.post('/api/device/keygen', json={'device_id': 'A'})
        client.post('/api/device/keygen', json={'device_id': 'B'})
        
        # Test empty message
        response = client.post('/api/message/send', json={
            'from': 'A', 'to': 'B', 'message': ''
        })
        assert response.status_code == 400
        
        # Test too long message
        response = client.post('/api/message/send', json={
            'from': 'A', 'to': 'B', 'message': 'x' * 1001
        })
        assert response.status_code == 400
        
        # Test same device
        response = client.post('/api/message/send', json={
            'from': 'A', 'to': 'A', 'message': 'test'
        })
        assert response.status_code == 400

class TestPCAPGeneration:
    """Test PCAP generation and download functionality"""
    
    @patch('unified_demo.pcap_gen')
    def test_pcap_download_success(self, mock_pcap_gen, client, reset_state):
        """Test successful PCAP download"""
        # Mock PCAP files
        mock_pcap_gen.get_pcap_files.return_value = [{
            'path': '/tmp/test.pcap',
            'name': 'qsafe_test.pcap'
        }]
        
        with patch('os.path.exists', return_value=True), \
             patch('unified_demo.send_file') as mock_send_file:
            mock_send_file.return_value = 'mock_file_response'
            
            response = client.get('/api/pcap/download')
            assert mock_send_file.called
    
    @patch('unified_demo.pcap_gen')
    def test_pcap_download_no_files(self, mock_pcap_gen, client, reset_state):
        """Test PCAP download when no files exist"""
        mock_pcap_gen.get_pcap_files.return_value = []
        mock_pcap_gen.create_sample_traffic.return_value = None
        
        response = client.get('/api/pcap/download')
        assert response.status_code == 404
        
        data = json.loads(response.data)
        assert 'error' in data
        assert 'No PCAP files available' in data['error']
    
    @patch('unified_demo.pcap_gen')
    def test_pcap_download_file_not_found(self, mock_pcap_gen, client, reset_state):
        """Test PCAP download when file doesn't exist"""
        mock_pcap_gen.get_pcap_files.return_value = [{
            'path': '/nonexistent/file.pcap',
            'name': 'test.pcap'
        }]
        
        response = client.get('/api/pcap/download')
        assert response.status_code == 404
        
        data = json.loads(response.data)
        assert 'error' in data
        assert 'not accessible' in data['error']

class TestDeviceCapture:
    """Test device capture and self-destruct functionality"""
    
    def test_device_capture_success(self, client, reset_state):
        """Test successful device capture with self-destruct"""
        # Set device online first
        qsafe_state['devices']['B']['status'] = 'online'
        
        response = client.post('/api/device/capture', 
                             json={'device_id': 'B'})
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert data['action'] == 'self_destruct_complete'
        assert qsafe_state['devices']['B']['status'] == 'compromised'
        assert qsafe_state['devices']['B']['keys'] is None
    
    def test_device_capture_already_compromised(self, client, reset_state):
        """Test capturing already compromised device"""
        qsafe_state['devices']['B']['status'] = 'compromised'
        
        response = client.post('/api/device/capture', 
                             json={'device_id': 'B'})
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert 'error' in data
        assert 'already compromised' in data['error']
    
    def test_device_capture_invalid_device(self, client, reset_state):
        """Test capturing invalid device"""
        response = client.post('/api/device/capture', 
                             json={'device_id': 'X'})
        assert response.status_code == 400
        
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Invalid device_id' in data['error']

class TestMissionControls:
    """Test mission control functionality"""
    
    def test_mission_start(self, client, reset_state):
        """Test mission start functionality"""
        response = client.post('/api/mission/start')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert qsafe_state['mission_running'] == True
        assert qsafe_state['mission_phase'] == 'KEY_EXCHANGE'
    
    def test_mission_stop(self, client, reset_state):
        """Test mission stop functionality"""
        qsafe_state['mission_running'] = True
        
        response = client.post('/api/mission/stop')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert qsafe_state['mission_running'] == False
        assert qsafe_state['mission_phase'] == 'STOPPED'
    
    def test_satellite_toggle(self, client, reset_state):
        """Test satellite toggle functionality"""
        initial_status = qsafe_state['satellite_online']
        
        response = client.post('/api/satellite/toggle')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['online'] != initial_status
        assert qsafe_state['satellite_online'] != initial_status

class TestToolLaunching:
    """Test external tool launching (Wireshark/Packet Tracer)"""
    
    @patch('os.path.exists')
    @patch('subprocess.Popen')
    def test_wireshark_launch_success(self, mock_popen, mock_exists, client, reset_state):
        """Test successful Wireshark launch"""
        mock_exists.return_value = True
        mock_popen.return_value = Mock()
        
        response = client.post('/api/launch_tool', json={
            'tool': 'wireshark',
            'file_path': '/tmp/test.pcap'
        })
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == True
        assert 'Wireshark launched' in data['message']
        assert mock_popen.called
    
    @patch('os.path.exists')
    def test_wireshark_not_found(self, mock_exists, client, reset_state):
        """Test Wireshark not found scenario"""
        mock_exists.return_value = False
        
        response = client.post('/api/launch_tool', json={
            'tool': 'wireshark',
            'file_path': '/tmp/test.pcap'
        })
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['success'] == False
        assert 'not found' in data['message']
        assert 'WIRESHARK_CMD' in data['instructions']

class TestLoggingSystem:
    """Test comprehensive logging system with standardized event schema"""
    
    def test_log_event_structure(self, reset_state):
        """Test log event has proper structure"""
        log_event('SECURE', 'Test message', 'TEST_DEVICE', {'test_key': 'test_value'})
        
        assert len(qsafe_state['logs']) > 0
        log = qsafe_state['logs'][-1]
        
        assert 'timestamp' in log
        assert 'level' in log
        assert 'message' in log
        assert 'device_id' in log
        assert 'color' in log
        assert 'metadata' in log
        assert log['level'] == 'SECURE'
        assert log['message'] == 'Test message'
        assert log['device_id'] == 'TEST_DEVICE'
        assert log['metadata']['test_key'] == 'test_value'
    
    def test_log_colors(self, reset_state):
        """Test log color coding"""
        log_event('SECURE', 'Secure message', 'TEST')
        log_event('WARNING', 'Warning message', 'TEST')
        log_event('BREACH', 'Breach message', 'TEST')
        
        logs = qsafe_state['logs'][-3:]
        assert logs[0]['color'] == '#00ff00'  # Green for SECURE
        assert logs[1]['color'] == '#ffff00'  # Yellow for WARNING
        assert logs[2]['color'] == '#ff0000'  # Red for BREACH
    
    def test_log_rotation(self, reset_state):
        """Test log rotation keeps only recent entries"""
        # Add more than 100 logs
        for i in range(105):
            log_event('INFO', f'Log message {i}', 'TEST')
        
        # Should keep only last 100
        assert len(qsafe_state['logs']) == 100
        assert 'Log message 104' in qsafe_state['logs'][-1]['message']

class TestReportGeneration:
    """Test report generation and ZIP download functionality"""
    
    @patch('unified_demo.report_gen')
    def test_report_generation_success(self, mock_report_gen, client, reset_state):
        """Test successful report generation"""
        mock_report_gen.create_evidence_package.return_value = '/tmp/evidence.zip'
        
        with patch('unified_demo.send_file') as mock_send_file:
            mock_send_file.return_value = 'mock_zip_response'
            
            response = client.get('/api/report/view')
            assert mock_send_file.called
            assert mock_report_gen.create_evidence_package.called
    
    @patch('unified_demo.report_gen')
    def test_report_generation_failure(self, mock_report_gen, client, reset_state):
        """Test report generation failure handling"""
        mock_report_gen.create_evidence_package.side_effect = Exception('Report generation failed')
        
        response = client.get('/api/report/view')
        assert response.status_code == 500
        
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Report generation failed' in data['error']

class TestIntegrationScenarios:
    """Test complete integration scenarios"""
    
    def test_full_mission_workflow(self, client, reset_state):
        """Test complete mission workflow"""
        # 1. Start mission
        response = client.post('/api/mission/start')
        assert response.status_code == 200
        
        # 2. Generate keys
        client.post('/api/device/keygen', json={'device_id': 'A'})
        client.post('/api/device/keygen', json={'device_id': 'B'})
        
        # 3. Send message
        response = client.post('/api/message/send', json={
            'from': 'A', 'to': 'B', 'message': 'Mission status update'
        })
        assert response.status_code == 200
        
        # 4. Simulate attack
        response = client.post('/api/attack/simulate', json={'attack_type': 'decrypt'})
        assert response.status_code == 200
        
        # 5. Capture device
        response = client.post('/api/device/capture', json={'device_id': 'B'})
        assert response.status_code == 200
        
        # 6. Stop mission
        response = client.post('/api/mission/stop')
        assert response.status_code == 200
        
        # Verify final state
        assert qsafe_state['stats']['messages_sent'] > 0
        assert qsafe_state['stats']['attacks_blocked'] > 0
        assert qsafe_state['devices']['B']['status'] == 'compromised'
        assert len(qsafe_state['logs']) > 10  # Should have many log entries

if __name__ == '__main__':
    # Run tests with verbose output
    pytest.main([__file__, '-v', '--tb=short'])
