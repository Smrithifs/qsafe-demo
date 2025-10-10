#!/usr/bin/env python3
"""
PCAP Generator with Scapy - Enhanced Evidence Collection
"""

import os
import json
import time
import hashlib
from datetime import datetime
from scapy.all import *

class PCAPGenerator:
    def __init__(self, output_dir="pcaps"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.current_session = None
        self.packet_counter = 0
        self.metadata = {}
        
    def start_session(self, session_type="mission"):
        """Start a new PCAP capture session"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.current_session = f"{session_type}_{timestamp}"
        self.packet_counter = 0
        self.metadata = {
            'session_id': self.current_session,
            'start_time': datetime.now().isoformat(),
            'packets': [],
            'messages': {}
        }
        return self.current_session
        
    def add_message_packet(self, msg_id, src_ip, dst_ip, payload_hex, signature_hex, 
                          alg_info, nonce=None, auth_tag=None):
        """Add a message packet to current PCAP session"""
        if not self.current_session:
            self.start_session()
            
        self.packet_counter += 1
        
        # Create packet with custom payload
        packet = IP(src=src_ip, dst=dst_ip) / UDP(sport=8080, dport=8080) / Raw(load=bytes.fromhex(payload_hex))
        
        # Add packet metadata
        packet_info = {
            'packet_number': self.packet_counter,
            'msg_id': msg_id,
            'timestamp': time.time(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'payload_hex': payload_hex,
            'signature_hex': signature_hex,
            'alg_info': alg_info,
            'nonce': nonce,
            'auth_tag': auth_tag,
            'packet_size': len(packet)
        }
        
        self.metadata['packets'].append(packet_info)
        self.metadata['messages'][msg_id] = packet_info
        
        # Write packet to PCAP
        pcap_file = os.path.join(self.output_dir, f"{self.current_session}.pcap")
        wrpcap(pcap_file, packet, append=True)
        
        return packet_info
        
    def add_mitm_packet(self, msg_id, attack_type, original_hex, modified_hex=None):
        """Add MITM attack packet to PCAP"""
        if not self.current_session:
            self.start_session("mitm")
            
        self.packet_counter += 1
        
        # Create MITM packet (attacker IP)
        payload = bytes.fromhex(modified_hex if modified_hex else original_hex)
        packet = IP(src="192.168.1.100", dst="192.168.1.1") / UDP(sport=9999, dport=8080) / Raw(load=payload)
        
        packet_info = {
            'packet_number': self.packet_counter,
            'msg_id': msg_id,
            'attack_type': attack_type,
            'timestamp': time.time(),
            'original_hex': original_hex,
            'modified_hex': modified_hex,
            'mitm_ip': "192.168.1.100",
            'packet_size': len(packet)
        }
        
        self.metadata['packets'].append(packet_info)
        
        # Write to MITM PCAP
        pcap_file = os.path.join(self.output_dir, f"{self.current_session}_mitm.pcap")
        wrpcap(pcap_file, packet, append=True)
        
        return packet_info
        
    def save_metadata(self):
        """Save packet metadata as JSON sidecar"""
        if not self.current_session:
            return None
            
        metadata_file = os.path.join(self.output_dir, f"{self.current_session}.json")
        self.metadata['end_time'] = datetime.now().isoformat()
        self.metadata['total_packets'] = self.packet_counter
        
        with open(metadata_file, 'w') as f:
            json.dump(self.metadata, f, indent=2)
            
        return metadata_file
        
    def get_pcap_files(self):
        """Get list of generated PCAP files"""
        if not self.current_session:
            return []
            
        files = []
        base_path = os.path.join(self.output_dir, self.current_session)
        
        for suffix in ['.pcap', '_mitm.pcap', '_replay.pcap']:
            file_path = base_path + suffix
            if os.path.exists(file_path):
                files.append({
                    'name': os.path.basename(file_path),
                    'path': file_path,
                    'size': os.path.getsize(file_path),
                    'type': suffix.replace('.pcap', '').replace('_', '')
                })
                
        return files
        
    def create_sample_traffic(self):
        """Create sample encrypted traffic for demo"""
        session_id = self.start_session("demo")
        
        # Sample encrypted messages
        messages = [
            {
                'msg_id': 'MSG_001',
                'src': '192.168.1.10',
                'dst': '192.168.1.20', 
                'payload': 'deadbeef' + 'a' * 64 + 'cafebabe',
                'signature': 'signature' + 'b' * 128,
                'alg': 'Kyber512+AES-GCM'
            },
            {
                'msg_id': 'MSG_002',
                'src': '192.168.1.20',
                'dst': '192.168.1.10',
                'payload': 'feedface' + 'c' * 64 + 'deadc0de', 
                'signature': 'signature' + 'd' * 128,
                'alg': 'Kyber512+AES-GCM'
            }
        ]
        
        for msg in messages:
            self.add_message_packet(
                msg['msg_id'], msg['src'], msg['dst'],
                msg['payload'], msg['signature'], msg['alg']
            )
            
        # Add MITM attempts
        self.add_mitm_packet('MSG_001', 'DECRYPT_ATTEMPT', messages[0]['payload'])
        self.add_mitm_packet('MSG_002', 'TAMPER_ATTEMPT', messages[1]['payload'], 
                           messages[1]['payload'].replace('feed', 'beef'))
        
        self.save_metadata()
        return session_id

if __name__ == '__main__':
    # Test PCAP generation
    pcap_gen = PCAPGenerator()
    session = pcap_gen.create_sample_traffic()
    print(f"Generated sample PCAP session: {session}")
    print(f"Files: {pcap_gen.get_pcap_files()}")
